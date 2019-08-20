const path = require('path');

const commonjs = require('rollup-plugin-commonjs');
const nodeResolve = require('rollup-plugin-node-resolve');
const typescript = require('rollup-plugin-typescript2');

const FORMAT = {
  CJS: 'cjs',
  ES: 'es',
};

const sourcePath = path.join(__dirname, 'src');
const outputPath = path.join(__dirname, 'dist');

const createNodeEntry = format => ({
  external: ['buffer/'],
  input: path.join(sourcePath, 'node.ts'),
  output: {
    format,
    file: path.join(outputPath, `node.${format}.js`),
  },
  plugins: [typescript({ useTsconfigDeclarationDir: true })],
});

const createBrowserEntry = format => ({
  input: path.join(sourcePath, 'browser.ts'),
  output: {
    format,
    file: path.join(outputPath, `browser.${format}.js`),
  },
  plugins: [
    nodeResolve({ browser: true }),
    commonjs(),
    typescript({ useTsconfigDeclarationDir: true }),
  ]
});

module.exports = [
  createBrowserEntry(FORMAT.CJS),
  createBrowserEntry(FORMAT.ES),
  createNodeEntry(FORMAT.CJS),
  createNodeEntry(FORMAT.ES),
];
