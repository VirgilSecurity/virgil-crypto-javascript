const benchmark = require('benchmark');
const fs = require('fs');
const path = require('path');

const runBenchmark = require('./benchmark');

const outputPath = path.join(__dirname, 'node.txt');

if (fs.existsSync(outputPath)) {
  fs.unlinkSync(outputPath);
}

const createLog = logPath => str => fs.appendFileSync(logPath, `${str}\n`);

const benchmarkLog = createLog(outputPath);

runBenchmark(benchmark, benchmarkLog);
