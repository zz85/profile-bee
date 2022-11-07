D3=https://d3js.org/d3.v7.js
D3_TIP=https://cdnjs.cloudflare.com/ajax/libs/d3-tip/0.9.1/d3-tip.min.js
D3_FLAMEGRAPH=https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.min.js

BOOTSTRAP_CSS=https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css
D3_FLAMEGRAPH_CSS=https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.css

cd $(dirname $0)

curl $D3 > scripts.js
curl $D3_TIP >> scripts.js
curl $D3_FLAMEGRAPH >> scripts.js

curl $BOOTSTRAP_CSS > styles.css
curl $D3_FLAMEGRAPH_CSS >> styles.css