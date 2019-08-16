const path = require('path');

const typescript = require('rollup-plugin-typescript2');

const FORMAT = {
  CJS: 'cjs',
  ES: 'es',
};

const sourcePath = path.join(__dirname, 'src');
const outputPath = path.join(__dirname, 'dist');
const browserEntry = path.join(sourcePath, 'browser.ts');
const nodeEntry = path.join(sourcePath, 'node.ts');

const createEntry = (entryPath, format) => ({
  external: ['buffer/'],
  input: entryPath,
  output: {
    format,
    file: path.join(outputPath, `${path.parse(entryPath).name}.${format}.js`),
  },
  plugins: [typescript({ useTsconfigDeclarationDir: true })],
});

module.exports = [
  createEntry(browserEntry, FORMAT.CJS),
  createEntry(browserEntry, FORMAT.ES),
  createEntry(nodeEntry, FORMAT.CJS),
  createEntry(nodeEntry, FORMAT.ES),
];
