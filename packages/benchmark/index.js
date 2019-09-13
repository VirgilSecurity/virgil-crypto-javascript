const fs = require('fs');
const path = require('path');

const benchmark = require('benchmark');
const webpack = require('webpack');

const runBenchmark = require('./benchmark');
const webpackConfig = require('./webpack.config');

const OUTPUT_FILE_PATH = path.join(__dirname, 'README.md');

const runNodeBenchmark = async () => {
  const lines = ['## Node.js'];
  await runBenchmark(benchmark, str => lines.push(str));
  return lines;
};

const runBrowserBenchmark = () =>
  new Promise(resolve => {
    const lines = [];
    lines.push('## Browser');
    webpack(webpackConfig, () => {
      resolve(lines);
    });
  });

(async () => {
  if (fs.existsSync(OUTPUT_FILE_PATH)) {
    fs.unlinkSync(OUTPUT_FILE_PATH);
    console.log(`${OUTPUT_FILE_PATH} was deleted`);
  }
  console.log('Running benchmarks. Please wait...');
  const [nodejsLines, browserLines] = await Promise.all([
    runNodeBenchmark(),
    runBrowserBenchmark(),
  ]);
  const lines = ['# Benchmarks', ...nodejsLines, ...browserLines];
  fs.writeFileSync(OUTPUT_FILE_PATH, lines.join('\n'));
  console.log(`${OUTPUT_FILE_PATH} was created`);
})();
