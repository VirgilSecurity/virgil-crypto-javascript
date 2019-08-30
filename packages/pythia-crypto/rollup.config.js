const path = require('path');

const commonjs = require('rollup-plugin-commonjs');
const nodeResolve = require('rollup-plugin-node-resolve');
const replace = require('rollup-plugin-re');
const { terser } = require('rollup-plugin-terser');
const typescript = require('rollup-plugin-typescript2');

const packageJson = require('./package.json');

const dependencies = Object.keys(packageJson.dependencies);

const FORMAT = {
  CJS: 'cjs',
  ES: 'es',
  UMD: 'umd',
};

const sourcePath = path.join(__dirname, 'src');
const outputPath = path.join(__dirname, 'dist');
const input = path.join(sourcePath, 'index.ts');

const createNonBundledEntry = (format, pythiaLibrary) => ({
  input,
  external: dependencies.concat([pythiaLibrary]),
  output: {
    format,
    file: path.join(outputPath, `${path.parse(pythiaLibrary).name}.js`),
  },
  plugins: [
    replace({
      patterns: [
        {
          match: /initPythia.ts$/,
          test: '@virgilsecurity/core-pythia',
          replace: pythiaLibrary,
        },
      ],
    }),
    typescript({
      exclude: ['**/*.test.ts'],
      useTsconfigDeclarationDir: true,
    }),
  ],
});

const createUmdEntry = (pythiaLibrary, outputFilename) => ({
  input,
  output: {
    format: 'umd',
    file: path.join(outputPath, outputFilename),
    name: 'VirgilPythiaCrypto',
  },
  plugins: [
    replace({
      patterns: [
        {
          match: /initPythia.ts$/,
          test: '@virgilsecurity/core-pythia',
          replace: pythiaLibrary,
        },
      ],
    }),
    nodeResolve({ browser: true }),
    commonjs(),
    typescript({
      exclude: ['**/*.test.ts'],
      useTsconfigDeclarationDir: true,
    }),
    terser(),
  ],
});

module.exports = [
  createUmdEntry('@virgilsecurity/core-pythia/browser.asmjs.es.js', 'browser.asmjs.umd.js'),
  createUmdEntry('@virgilsecurity/core-pythia/browser.es.js', 'browser.umd.js'),
  createUmdEntry('@virgilsecurity/core-pythia/worker.asmjs.es.js', 'worker.asmjs.umd.js'),
  createUmdEntry('@virgilsecurity/core-pythia/worker.es.js', 'worker.umd.js'),
  createNonBundledEntry(FORMAT.CJS, '@virgilsecurity/core-pythia/browser.asmjs.cjs.js'),
  createNonBundledEntry(FORMAT.ES, '@virgilsecurity/core-pythia/browser.asmjs.es.js'),
  createNonBundledEntry(FORMAT.CJS, '@virgilsecurity/core-pythia/browser.cjs.js'),
  createNonBundledEntry(FORMAT.ES, '@virgilsecurity/core-pythia/browser.es.js'),
  createNonBundledEntry(FORMAT.CJS, '@virgilsecurity/core-pythia/node.asmjs.cjs.js'),
  createNonBundledEntry(FORMAT.ES, '@virgilsecurity/core-pythia/node.asmjs.es.js'),
  createNonBundledEntry(FORMAT.CJS, '@virgilsecurity/core-pythia/node.cjs.js'),
  createNonBundledEntry(FORMAT.ES, '@virgilsecurity/core-pythia/node.es.js'),
  createNonBundledEntry(FORMAT.CJS, '@virgilsecurity/core-pythia/worker.asmjs.cjs.js'),
  createNonBundledEntry(FORMAT.ES, '@virgilsecurity/core-pythia/worker.asmjs.es.js'),
  createNonBundledEntry(FORMAT.CJS, '@virgilsecurity/core-pythia/worker.cjs.js'),
  createNonBundledEntry(FORMAT.ES, '@virgilsecurity/core-pythia/worker.es.js'),
];
