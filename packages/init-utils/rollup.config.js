const path = require('path');

const typescript = require('rollup-plugin-typescript2');

const { FORMAT, getOutputFilename } = require('../../utils/build');

const sourcePath = path.join(__dirname, 'src');
const outputPath = path.join(__dirname, 'dist');

const createEntry = (format, isNodeES) => ({
  external: ['eventemitter3'],
  input: path.join(sourcePath, 'index.ts'),
  output: {
    format,
    file: path.join(
      outputPath,
      getOutputFilename('init-utils', undefined, format, isNodeES ? 'mjs' : 'js'),
    ),
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

module.exports = [createEntry(FORMAT.CJS), createEntry(FORMAT.ES), createEntry(FORMAT.ES, true)];
