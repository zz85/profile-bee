use futures_util::{Stream, StreamExt};
/// this modules generates a d3 html page that views
/// profile stacktraces in an interactive flamegraph format
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    cell::RefCell,
    path::Path,
    rc::Rc,
    sync::{Arc, Mutex},
};
use tokio::sync::{broadcast::Receiver, mpsc};
use tokio_stream::wrappers::UnboundedReceiverStream;
use warp::sse::Event;

/// hierarchical data structure
/// in the form of { name, value, c, children }
///
/// `c` is the category+hash color (`#rrggbb`) computed server-side so the HTML
/// viewer colors frames identically to the SVG and TUI renderers.
#[derive(Serialize, Deserialize, Default)]
struct Stack<'a> {
    name: &'a str,
    value: usize,
    #[serde(rename = "c")]
    color: String,
    children: Vec<Rc<RefCell<Stack<'a>>>>,
}

impl<'a> Stack<'a> {
    fn new(name: &'a str) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            name,
            color: frame_color_hex(name),
            ..Default::default()
        }))
    }
}

/// Category+hash color for a frame name as a `#rrggbb` hex string.
fn frame_color_hex(name: &str) -> String {
    let (r, g, b) = profile_bee_common::color::color_for(name);
    format!("#{:02x}{:02x}{:02x}", r, g, b)
}

/// starts a local server that serves the flamegraph html file
pub async fn start_server(rx: Receiver<String>) {
    start_server_on_port(rx, 8000).await;
}

/// starts a local server on the specified port that serves the flamegraph html file
pub async fn start_server_on_port(mut rx: Receiver<String>, port: u16) {
    use warp::Filter;

    let latest_data = Arc::new(Mutex::new("{}".to_string()));
    let subscribers = Arc::new(Mutex::new(Vec::<mpsc::UnboundedSender<String>>::new()));
    let access_subscribers = subscribers.clone();
    let subscriptions = warp::any().map(move || subscribers.clone());

    let writer = latest_data.clone();
    tokio::spawn(async move {
        tracing::debug!("start_server: broadcast receiver task started, waiting for data");
        while let Ok(data) = rx.recv().await {
            tracing::info!(
                "start_server: received broadcast data ({} bytes)",
                data.len()
            );
            let mut write = writer.lock().expect("poisoned");
            *write = data.clone();
            drop(write);

            let mut write = access_subscribers.lock().expect("poisoned");
            write.retain(|tx| tx.send(data.clone()).is_ok());
            tracing::info!("start_server: {} realtime SSE subscribers", write.len());
        }
        tracing::warn!("start_server: broadcast receiver loop ended (sender dropped)");
    });

    let json_copy = latest_data.clone();
    // GET /json -> stack trace json
    let json = warp::path("json").and(warp::get()).map(move || {
        tracing::debug!("start_server: GET /json request");
        let json = json_copy.lock().expect("poisoned").clone();

        warp::http::Response::builder()
            .header("content-type", "application/json")
            .body(json)
    });

    // GET /stream -> subscribe to profiling data updates
    let stream = warp::path("stream")
        .and(warp::get())
        .and(subscriptions)
        .map(|subscriptions| {
            tracing::info!("start_server: GET /stream - new SSE subscriber");
            let stream = connected(subscriptions);

            // returns a stream when replies is sent via server-sent events
            warp::sse::reply(warp::sse::keep_alive().stream(stream))
        });

    // GET / -> index html
    let index = warp::path::end().map(move || {
        tracing::debug!("start_server: GET / request");
        let json_copy = latest_data.lock().expect("poisoned");

        warp::http::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(flamegraph_html_with_mode(&json_copy, true))
    });

    tracing::info!("Web server listening on http://127.0.0.1:{}/", port);
    warp::serve(index.or(json).or(stream))
        .run(([127, 0, 0, 1], port))
        .await;
    tracing::warn!("start_server: warp server exited");
}

fn connected(
    subscriptions: Arc<Mutex<Vec<mpsc::UnboundedSender<String>>>>,
) -> impl Stream<Item = Result<Event, warp::Error>> + Send + 'static {
    tracing::info!("connected: new SSE subscription registered");

    // Use an unbounded channel to handle buffering and flushing of messages
    // to the event source...
    let (tx, rx) = mpsc::unbounded_channel();
    let rx = UnboundedReceiverStream::new(rx);

    // Push a tx channel so we have a way to reach out to all connected users.
    subscriptions.lock().unwrap().push(tx);

    rx.map(|msg| Ok(Event::default().data(msg)))
}

/// turns a sorted stackcollapsed format into flamegraph json format
pub fn collapse_to_json(stacks: &[&str]) -> String {
    let root = Stack::new("");
    let mut crumbs = vec![root.clone()];

    for stack in stacks {
        // Split the trailing ` <count>` from the right: frame names can contain
        // spaces (process roots like `node (1234)`, V8 frames like
        // `processData (server.js:42)`), so splitting on the first space would
        // truncate the stack. This mirrors the collapse parsing elsewhere
        // (`build_collapse_output`, the SVG palette builder, the TUI `flame`).
        let (frames_str, count) = match stack.rsplit_once(' ') {
            Some((frames, count_str)) => {
                (frames, count_str.trim().parse::<usize>().ok().unwrap_or(1))
            }
            None => (*stack, 1),
        };
        let names = frames_str.split(';');

        let mut depth = 0;

        for name in names {
            depth += 1;

            if depth >= crumbs.len() || name != crumbs[depth].borrow().name {
                // new flow
                crumbs.truncate(depth);

                let node = Stack::new(name);

                crumbs[depth - 1].borrow_mut().children.push(node.clone());
                crumbs.push(node);
            }
        }

        if depth + 1 != crumbs.len() {
            crumbs.truncate(depth + 1);
        }

        let self_value = false;
        if self_value {
            // if we were to use selfValue(true), this inserts values only
            // at leave nodes
            crumbs
                .last()
                .unwrap_or_else(|| unreachable!("always have one"))
                .borrow_mut()
                .value += count;
        } else {
            // adds count to all nodes along the path
            for node in crumbs.iter() {
                node.borrow_mut().value += count;
            }
        }
    }

    serde_json::to_string(&root).expect("serialization to json")
}

pub fn generate_html_file(filename: &Path, data: &str) -> std::io::Result<()> {
    let html = flamegraph_html(data);
    std::fs::write(filename, html)
}

// Self-contained HTML template — no external JS/CSS dependencies
const HTML_TEMPLATE: &str = include_str!("../assets/flamegraph.html");

fn flamegraph_html(stacks: &str) -> String {
    flamegraph_html_with_mode(stacks, false)
}

fn flamegraph_html_with_mode(stacks: &str, serve: bool) -> String {
    let safe_stacks = stacks.replace("</", "<\\/");
    HTML_TEMPLATE
        .replace("{title}", "profile-bee")
        .replace("{serve_mode}", if serve { "true" } else { "false" })
        .replace("{stack}", &safe_stacks)
}

#[test]
fn test_serialization() {
    let x = [
        "a 1",
        "a;b 1",
        "a;b 1",
        "a;b;c 1",
        "a;b;c;d 1",
        "a;b;e 3",
        "f;g 1",
    ];

    let parsed: serde_json::Value = serde_json::from_str(&collapse_to_json(&x)).unwrap();

    // Structure + aggregated values are unchanged by the color field.
    assert_eq!(parsed["name"], "");
    assert_eq!(parsed["value"], 9);
    let a = &parsed["children"][0];
    assert_eq!(a["name"], "a");
    assert_eq!(a["value"], 8);
    let b = &a["children"][0];
    assert_eq!(b["name"], "b");
    assert_eq!(b["value"], 7);

    // Every named node carries its category+hash color under key "c".
    fn check_colors(node: &serde_json::Value) {
        let name = node["name"].as_str().unwrap();
        if !name.is_empty() {
            assert_eq!(node["c"].as_str().unwrap(), frame_color_hex(name));
        }
        if let Some(children) = node["children"].as_array() {
            for child in children {
                check_colors(child);
            }
        }
    }
    check_colors(&parsed);

    // A manually built Stack serializes the color field ("" by default here).
    let mut test = Stack {
        name: "hi",
        value: 10,
        ..Default::default()
    };
    let test1 = Stack {
        name: "test 1",
        value: 3,
        ..Default::default()
    };
    let test2 = Stack {
        name: "test 2",
        value: 4,
        ..Default::default()
    };
    test.children.push(Rc::new(RefCell::new(test1)));
    test.children.push(Rc::new(RefCell::new(test2)));

    let test_json = serde_json::to_string(&test).expect("serialization to json");

    assert_eq!(
        test_json,
        r##"{"name":"hi","value":10,"c":"","children":[{"name":"test 1","value":3,"c":"","children":[]},{"name":"test 2","value":4,"c":"","children":[]}]}"##
    );
}

#[test]
fn test_varying_depth_stacks() {
    // This test specifically checks the truncate bug
    // When we go from deep stack to shallow stack,
    // the crumbs should be truncated correctly
    let stacks = [
        "a;b;c 1", "a;b 1",   // Shallower than previous
        "a;b;d 1", // Same depth but different branch
        "a 1",     // Even shallower
        "a;e 1",   // Back to depth 2
    ];

    let json = collapse_to_json(stacks.as_ref());

    // Parse the JSON to verify it's valid
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Valid JSON");

    // Verify structure
    assert_eq!(parsed["name"], "");
    let children = parsed["children"].as_array().unwrap();
    assert_eq!(children.len(), 1); // Should have one root child "a"

    let a = &children[0];
    assert_eq!(a["name"], "a");
    assert_eq!(a["value"], 5); // Sum of all stacks

    let a_children = a["children"].as_array().unwrap();
    assert_eq!(a_children.len(), 2); // Should have "b" and "e"

    // Find b and e
    let b = a_children.iter().find(|c| c["name"] == "b").unwrap();
    let e = a_children.iter().find(|c| c["name"] == "e").unwrap();

    assert_eq!(b["value"], 3); // a;b;c + a;b + a;b;d
    assert_eq!(e["value"], 1); // a;e

    let b_children = b["children"].as_array().unwrap();
    assert_eq!(b_children.len(), 2); // Should have "c" and "d"
}

#[test]
fn test_frame_names_with_spaces() {
    // Frame names can contain spaces (process roots, V8/JS frames). The count
    // must be split from the RIGHT so these names survive intact — otherwise
    // the whole stack collapses to its first space-delimited token.
    let stacks = [
        "node (1234);main;processData (server.js:42) 5",
        "node (1234);main;compute 3",
    ];
    let json = collapse_to_json(&stacks);
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Valid JSON");

    let root_child = &parsed["children"][0];
    assert_eq!(root_child["name"], "node (1234)");
    assert_eq!(root_child["value"], 8); // 5 + 3

    let main = &root_child["children"][0];
    assert_eq!(main["name"], "main");
    let leaves: Vec<&str> = main["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(leaves.contains(&"processData (server.js:42)"));
    assert!(leaves.contains(&"compute"));
}
