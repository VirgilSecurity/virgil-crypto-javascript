const path = require('path');

const typescript = require('rollup-plugin-typescript2');

const packageJson = require('./package.json');

const external = Object.keys(packageJson.dependencies);

const formats = ['cjs', 'es'];

const sourcePath = path.join(__dirname, 'src');
const outputPath = path.join(__dirname, 'dist');

const createEntry = format => ({
  external,
  input: path.join(sourcePath, 'index.ts'),
  output: {
    format,
    file: path.join(outputPath, `base-crypto.${format}.js`),
  },
  plugins: [typescript({ useTsconfigDeclarationDir: true })],
});

module.exports = formats.map(createEntry);
