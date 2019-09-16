/* eslint-env browser */

require('core-js/stable');
require('regenerator-runtime/runtime');

const runBenchmark = require('./benchmark');

(async () => {
  const lines = ['## Browser'];
  await runBenchmark(window.Benchmark, str => lines.push(str));
  await fetch('/lines', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ lines }),
  });
  const doneElement = document.createElement('div');
  doneElement.id = 'done';
  document.body.appendChild(doneElement);
})();
