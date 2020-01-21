const fs = require('fs');
const http = require('http');
const path = require('path');
const os = require('os');
const osName = require('os-name');

const benchmark = require('benchmark');
const puppeteer = require('puppeteer');
const serveHandler = require('serve-handler');
const webpack = require('webpack');

const runBenchmark = require('./benchmark');
const webpackConfig = require('./webpack.config');

const SERVER_PORT = 3000;
const OUTPUT_FILE_PATH = path.join(__dirname, 'README.md');

const getSystemInfo = () =>
  `\nResults below were obtained on ${osName()} with ${os.cpus()[0].model}\n`;

const runNodeBenchmark = async () => {
  const lines = [`## Node.js (Version: ${process.version})\n`];
  await runBenchmark(benchmark, str => lines.push(str));
  return lines;
};

const runBrowserBenchmark = async () => {
  const browser = await puppeteer.launch();
  return new Promise(resolve => {
    const server = http.createServer((request, response) => {
      if (request.method === 'POST' && request.url === '/lines') {
        let body = '';
        request.on('data', chunk => {
          body += chunk;
        });
        request.on('end', () => {
          response.end();
          server.close(async () => {
            await browser.close();
            resolve(JSON.parse(body).lines);
          });
        });
      } else {
        serveHandler(request, response, {
          public: webpackConfig.output.path,
          directoryListing: false,
          headers: [
            {
              source: '*.wasm',
              headers: [{ key: 'Content-Type', value: 'application/wasm' }],
            },
          ],
        });
      }
    });
    webpack(webpackConfig, () => {
      server.listen(SERVER_PORT, async () => {
        const page = await browser.newPage();
        await page.goto(`http://localhost:${SERVER_PORT}`);
        await page.waitForSelector('#done', { timeout: 0 });
      });
    });
  });
};

(async () => {
  console.log('Running benchmarks. This process can take several minutes. Please wait...');
  const [nodejsLines, browserLines] = await Promise.all([
    runNodeBenchmark(),
    runBrowserBenchmark(),
  ]);
  const lines = ['# Benchmarks', getSystemInfo(), ...nodejsLines, ...browserLines];
  fs.writeFileSync(OUTPUT_FILE_PATH, lines.join('\n'));
  console.log(`${OUTPUT_FILE_PATH} was created`);
})();
