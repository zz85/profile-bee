/// this modules generates a d3 html page that views
/// profile stacktraces in an interactive flamegraph format
use serde::{Deserialize, Serialize};
use serde_json;
use std::{cell::RefCell, path::Path, rc::Rc};

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

/// turns a sorted stackcollapsed format into d3-flamegraph json format
pub fn collapse_to_json(stacks: &[&str]) -> String {
    let root = Stack::new("");
    let mut crumbs = vec![root.clone()];

    for stack in stacks {
        let mut parts = stack.split(' ');
        let mut names = parts.next().map(|v| v.split(";")).expect("stack");
        let count = parts
            .next()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);

        let mut depth = 0;

        while let Some(name) = names.next() {
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
            crumbs.truncate(depth);
        }

        let self_value = true;
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

pub fn generate_html_file(filename: &Path, stacks: &[&str]) {
    let data = collapse_to_json(stacks);
    let html = flamegraph_html(&data);
    std::fs::write(&filename, &html).expect("Unable to write stack html file");
}

// Uses https://github.com/spiermar/d3-flame-graph
const HTML_TEMPLATE: &str = include_str!("../assets/d3-flamegraph.html");

fn flamegraph_html(stacks: &str) -> String {
    HTML_TEMPLATE
        .replace("{stack}", stacks)
        .replace("{title}", "profile-bee")
}
