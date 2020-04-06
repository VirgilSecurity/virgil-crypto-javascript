const path = require('path');

const typescript = require('rollup-plugin-typescript2');

const formats = ['cjs', 'es'];

const sourcePath = path.join(__dirname, 'src');
const outputPath = path.join(__dirname, 'dist');

const createEntry = format => ({
  external: ['eventemitter3'],
  input: path.join(sourcePath, 'index.ts'),
  output: {
    format,
    file: path.join(outputPath, `init-utils.${format}.js`),
  },
  plugins: [
    typescript({
      useTsconfigDeclarationDir: true,
      tsconfigOverride: {
        compilerOptions: {
          declarationDir: path.join(outputPath, 'types'),
        },
        exclude: [outputPath, '**/*.test.ts'],
      },
    }),
  ],
});

module.exports = formats.map(createEntry);
