/* eslint-env browser */

const runBenchmark = require('./benchmark');

(async () => {
  const lines = ['## Browser'];
  await runBenchmark(window.Benchmark, str => lines.push(str));
  console.log(lines);
})();
