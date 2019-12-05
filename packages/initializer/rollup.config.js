const path = require('path');

const typescript = require('rollup-plugin-typescript2');

const formats = ['cjs', 'es'];

const sourcePath = path.join(__dirname, 'src');
const outputPath = path.join(__dirname, 'dist');

const createEntry = format => ({
  input: path.join(sourcePath, 'index.ts'),
  output: {
    format,
    file: path.join(outputPath, `initializer.${format}.js`),
  },
  plugins: [typescript({ useTsconfigDeclarationDir: true })],
});

module.exports = formats.map(createEntry);
