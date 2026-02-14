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
/// in the form of { name, value, children }
#[derive(Serialize, Deserialize, Default)]
struct Stack<'a> {
    name: &'a str,
    value: usize,
    children: Vec<Rc<RefCell<Stack<'a>>>>,
}

impl<'a> Stack<'a> {
    fn new(name: &'a str) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            name,
            ..Default::default()
        }))
    }
}

/// starts a local server that serves ht flmaegraph html file
pub async fn start_server(mut rx: Receiver<String>) {
    use warp::Filter;

    let latest_data = Arc::new(Mutex::new("{}".to_string()));
    let subscribers = Arc::new(Mutex::new(Vec::<mpsc::UnboundedSender<String>>::new()));
    let access_subscribers = subscribers.clone();
    let subscriptions = warp::any().map(move || subscribers.clone());

    let writer = latest_data.clone();
    tokio::spawn(async move {
        while let Ok(data) = rx.recv().await {
            println!("Received....");
            let mut write = writer.lock().expect("poisoned");
            *write = data.clone();
            drop(write);

            let mut write = access_subscribers.lock().expect("poisoned");
            write.retain(|tx| tx.send(data.clone()).is_ok());
            println!("{} realtime subscribers", write.len());
        }
    });

    let json_copy = latest_data.clone();
    // GET /json -> stack trace json
    let json = warp::path("json").and(warp::get()).map(move || {
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
            let stream = connected(subscriptions);

            // returns a stream when replies is sent via server-sent events
            warp::sse::reply(warp::sse::keep_alive().stream(stream))
        });

    // GET / -> index html
    let index = warp::path::end().map(move || {
        let json_copy = latest_data.lock().expect("poisoned");

        warp::http::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(flamegraph_html(&json_copy))
    });

    eprintln!("Listening on port 8000. Goto http://localhost:8000/");
    warp::serve(index.or(json).or(stream))
        .run(([127, 0, 0, 1], 8000))
        .await;
}

fn connected(
    subscriptions: Arc<Mutex<Vec<mpsc::UnboundedSender<String>>>>,
) -> impl Stream<Item = Result<Event, warp::Error>> + Send + 'static {
    println!("new subscription");

    // Use an unbounded channel to handle buffering and flushing of messages
    // to the event source...
    let (tx, rx) = mpsc::unbounded_channel();
    let rx = UnboundedReceiverStream::new(rx);

    // Push a tx channel so we have a way to reach out to all connected users.
    subscriptions.lock().unwrap().push(tx);

    rx.map(|msg| Ok(Event::default().data(msg)))
}

/// turns a sorted stackcollapsed format into d3-flamegraph json format
pub fn collapse_to_json(stacks: &[&str]) -> String {
    let root = Stack::new("");
    let mut crumbs = vec![root.clone()];

    for stack in stacks {
        let mut parts = stack.split(' ');
        let names = parts.next().map(|v| v.split(';')).expect("stack");
        let count = parts
            .next()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);

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

pub fn generate_html_file(filename: &Path, data: &str) {
    let html = flamegraph_html(data);
    std::fs::write(filename, html).expect("Unable to write stack html file");
}

// Uses https://github.com/spiermar/d3-flame-graph
const HTML_TEMPLATE: &str = include_str!("../assets/d3-flamegraph.html");
const SCRIPTS: &str = include_str!("../assets/scripts.js");
const STYLES: &str = include_str!("../assets/styles.css");

const EXTERNAL_SCRIPTS: &str = r#"<script src="https://d3js.org/d3.v7.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3-tip/0.9.1/d3-tip.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.min.js"></script>"#;

const EXTERNAL_STYLES: &str = r#"
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" />
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.css" />"#;

fn flamegraph_html(stacks: &str) -> String {
    let embedded = true;

    let template = HTML_TEMPLATE
        .replace("{stack}", stacks)
        .replace("{title}", "profile-bee");

    if embedded {
        template
            .replace("{scripts}", &format!("<script>{}</script>", SCRIPTS))
            .replace("{styles}", &format!("<style>{}</style>", STYLES))
    } else {
        template
            .replace("{scripts}", EXTERNAL_SCRIPTS)
            .replace("{styles}", EXTERNAL_STYLES)
    }
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

    assert_eq!(
        collapse_to_json(&x),
        r##"{"name":"","value":9,"children":[{"name":"a","value":8,"children":[{"name":"b","value":7,"children":[{"name":"c","value":2,"children":[{"name":"d","value":1,"children":[]}]},{"name":"e","value":3,"children":[]}]}]},{"name":"f","value":1,"children":[{"name":"g","value":1,"children":[]}]}]}"##
    );

    let mut test = Stack::default();
    test.name = "hi";
    test.value = 10;
    let mut test1 = Stack::default();
    test1.name = "test 1";
    test1.value = 3;
    let mut test2 = Stack::default();
    test2.name = "test 2";
    test2.value = 4;
    test.children.push(Rc::new(RefCell::new(test1)));
    test.children.push(Rc::new(RefCell::new(test2)));

    let test_json = serde_json::to_string(&test).expect("serialization to json");

    assert_eq!(
        test_json,
        r##"{"name":"hi","value":10,"children":[{"name":"test 1","value":3,"children":[]},{"name":"test 2","value":4,"children":[]}]}"##
    );
}

#[test]
fn test_varying_depth_stacks() {
    // This test specifically checks the truncate bug
    // When we go from deep stack to shallow stack,
    // the crumbs should be truncated correctly
    let stacks = [
        "a;b;c 1",
        "a;b 1",   // Shallower than previous
        "a;b;d 1", // Same depth but different branch
        "a 1",     // Even shallower
        "a;e 1",   // Back to depth 2
    ];

    let json = collapse_to_json(&stacks.iter().map(|s| *s).collect::<Vec<_>>());

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
