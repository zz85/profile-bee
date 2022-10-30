/// this modules generates a d3 html page that views
/// profile stacktraces in an interactive flamegraph format
use serde::{Deserialize, Serialize};
use serde_json;
use std::{cell::RefCell, path::Path, sync::Arc};

/// hierarchical data structure
/// in the form of { name, value, children }
#[derive(Serialize, Deserialize, Default)]
struct Stack {
    name: String,
    value: usize,
    children: Vec<Arc<RefCell<Stack>>>,
}

/// turns a sorted stackcollapsed format into d3-flamegraph json format
pub fn collapse_to_json(stacks: &[&str]) -> String {
    let root = Arc::new(RefCell::new(Stack::default()));
    let mut crumbs: Vec<Arc<RefCell<Stack>>> = vec![root.clone()];

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

                let mut node = Stack::default();
                node.name = name.to_owned();

                let anode = Arc::new(RefCell::new(node));

                let last = crumbs
                    .last()
                    .unwrap_or_else(|| unreachable!("last entry in stacks"));

                last.borrow_mut().children.push(anode.clone());

                crumbs.push(anode);
            }
        }

        if depth + 1 != crumbs.len() {
            crumbs.truncate(depth);
        }

        for node in crumbs.iter() {
            node.borrow_mut().value += count;
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
    test.name = "hi".to_string();
    test.value = 10;
    let mut test1 = Stack::default();
    test1.name = "test 1".to_string();
    test1.value = 3;
    let mut test2 = Stack::default();
    test2.name = "test 2".to_string();
    test2.value = 4;
    test.children.push(Arc::new(RefCell::new(test1)));
    test.children.push(Arc::new(RefCell::new(test2)));

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
const HTML_TEMPLATE: &str = r##"
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/gh/spiermar/d3-flame-graph@1.0.4/dist/d3.flameGraph.min.css">
    <style>
    /* Space out content a bit */
    body {
      padding-top: 20px;
      padding-bottom: 20px;
    }
    /* Custom page header */
    .header {
      padding-bottom: 20px;
      padding-right: 15px;
      padding-left: 15px;
      border-bottom: 1px solid #e5e5e5;
    }
    /* Make the masthead heading the same height as the navigation */
    .header h3 {
      margin-top: 0;
      margin-bottom: 0;
      line-height: 40px;
    }
    /* Customize container */
    .container {
      max-width: 990px;
    }
    </style>
    <title>{title}</title>
    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>
  <body>
    <div class="container">
      <div class="header clearfix">
        <nav>
          <div class="pull-right">
            <form class="form-inline" id="form">
              <a class="btn" href="javascript: resetZoom();">Reset zoom</a>
              <a class="btn" href="javascript: clear();">Clear</a>
              <div class="form-group">
                <input type="text" class="form-control" id="term">
              </div>
              <a class="btn btn-primary" href="javascript: search();">Search</a>
            </form>
          </div>
        </nav>
        <h3 class="text-muted">{title}</h3>
      </div>
      <div id="chart">
      </div>
      <hr>
      <div id="details">
      </div>
    </div>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/d3/4.10.0/d3.min.js"></script>
      <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/d3-tip/0.7.1/d3-tip.min.js"></script>
      <script type="text/javascript" src="https://cdn.jsdelivr.net/gh/spiermar/d3-flame-graph@1.0.4/dist/d3.flameGraph.min.js"></script>
    <script type="text/javascript">
        var data = {stack};
    </script>
    <script type="text/javascript">
    var flameGraph = d3.flameGraph()
      .width(960)
      .cellHeight(18)
      .transitionDuration(750)
      .transitionEase(d3.easeCubic)
      .sort(!true)
      .title("")
      .onClick(onClick);
    // Example on how to use custom tooltips using d3-tip.
    var tip = d3.tip()
      .direction("s")
      .offset([8, 0])
      .attr('class', 'd3-flame-graph-tip')
      .html(function(d) { return "name: " + d.data.name + ", value: " + d.data.value; });
    flameGraph.tooltip(tip);
    d3.select("#chart")
      .datum(data)
      .call(flameGraph);
    document.getElementById("form").addEventListener("submit", function(event){
      event.preventDefault();
      search();
    });
    function search() {
      var term = document.getElementById("term").value;
      flameGraph.search(term);
    }
    function clear() {
      document.getElementById('term').value = '';
      flameGraph.clear();
    }
    function resetZoom() {
      flameGraph.resetZoom();
    }
    function onClick(d) {
      console.info("Clicked on " + d.data.name);
    }
    </script>
  </body>
</html>
"##;

fn flamegraph_html(stacks: &str) -> String {
    HTML_TEMPLATE
        .replace("{stack}", stacks)
        .replace("{title}", "profile-bee")
}
