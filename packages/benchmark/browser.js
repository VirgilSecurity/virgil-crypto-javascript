const runBenchmark = require('./benchmark');

const log = str => {
  const div = document.createElement('div');
  const textNode = document.createTextNode(str);
  div.appendChild(textNode);
  document.body.appendChild(div);
};

runBenchmark(window.Benchmark, log);
