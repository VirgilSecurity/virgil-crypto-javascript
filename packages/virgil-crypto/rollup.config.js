const path = require('path');

const commonjs = require('rollup-plugin-commonjs');
const nodeResolve = require('rollup-plugin-node-resolve');
const { terser } = require('rollup-plugin-terser');

const sourcePath = path.join(__dirname, 'dist');
const outputPath = path.join(__dirname, 'dist');

const createBundle = (entryName, outputName) => ({
  input: path.join(sourcePath, entryName),
  output: {
    format: 'umd',
    file: path.join(outputPath, outputName),
    name: 'VirgilCrypto',
  },
  plugins: [
    nodeResolve({ browser: true }),
    commonjs(),
    terser(),
  ],
});

module.exports = [
  createBundle('browser.asmjs.es.js', 'browser.asmjs.umd.js'),
  createBundle('browser.es.js', 'browser.umd.js'),
  createBundle('worker.asmjs.es.js', 'worker.asmjs.umd.js'),
  createBundle('worker.es.js', 'worker.umd.js'),
];
