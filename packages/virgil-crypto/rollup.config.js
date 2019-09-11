const path = require('path');

const builtinModules = require('builtin-modules');
const commonjs = require('rollup-plugin-commonjs');
const copy = require('rollup-plugin-copy');
const nodeResolve = require('rollup-plugin-node-resolve');
const replace = require('rollup-plugin-re');
const { terser } = require('rollup-plugin-terser');
const typescript = require('rollup-plugin-typescript2');

const packageJson = require('./package.json');

const FORMAT = {
  CJS: 'cjs',
  ES: 'es',
  UMD: 'umd',
};

const CRYPTO_TYPE = {
  WASM: 'wasm',
  ASMJS: 'asmjs',
};

const TARGET = {
  BROWSER: 'browser',
  WORKER: 'worker',
  NODE: 'node',
};

const sourceDir = path.join(__dirname, 'src');
const outputDir = path.join(__dirname, 'dist');

const getOutputFilename = (target, cryptoType, format) =>
  `${target}${cryptoType === CRYPTO_TYPE.ASMJS ? '.asmjs' : ''}.${format}.js`;

const getCryptoEntryPointName = (target, cryptoType) =>
  `${target}${cryptoType === CRYPTO_TYPE.ASMJS ? '.asmjs' : ''}.es.js`;

const createBrowserEntry = (target, cryptoType, format) => ({
  input: path.join(sourceDir, 'index.ts'),
  output: {
    format,
    file: path.join(outputDir, getOutputFilename(target, cryptoType, format)),
    name: 'VirgilCrypto',
  },
  plugins: [
    replace({
      patterns: [
        {
          match: /index\.ts$/,
          test: '@virgilsecurity/core-foundation',
          replace: path.join(
            '@virgilsecurity',
            'core-foundation',
            getCryptoEntryPointName(target, cryptoType),
          ),
        },
      ],
    }),
    nodeResolve({ browser: true, extensions: ['.js', '.ts'] }),
    commonjs(),
    typescript({
      exclude: ['**/*.test.ts'],
      objectHashIgnoreUnknownHack: true,
      useTsconfigDeclarationDir: true,
    }),
    cryptoType === CRYPTO_TYPE.WASM &&
      copy({
        targets: [
          {
            src: path.join(
              __dirname,
              'node_modules',
              '@virgilsecurity',
              'core-foundation',
              `libfoundation.${target}.wasm`,
            ),
            dest: outputDir,
          },
        ],
      }),
    format === FORMAT.UMD && terser(),
  ],
});

const createNodeJsEntry = (cryptoType, format) => ({
  input: path.join(sourceDir, 'index.ts'),
  output: {
    format,
    file: path.join(outputDir, getOutputFilename(TARGET.NODE, cryptoType, format)),
  },
  external: builtinModules.concat(Object.keys(packageJson.dependencies)),
  plugins: [
    replace({
      patterns: [
        {
          match: /index\.ts$/,
          test: '@virgilsecurity/core-foundation',
          replace: path.join(
            '@virgilsecurity',
            'core-foundation',
            getCryptoEntryPointName(TARGET.NODE, cryptoType),
          ),
        },
      ],
    }),
    nodeResolve({ extensions: ['.js', '.ts'] }),
    commonjs(),
    typescript({
      exclude: ['**/*.test.ts'],
      useTsconfigDeclarationDir: true,
    }),
  ],
});

module.exports = [
  createBrowserEntry(TARGET.BROWSER, CRYPTO_TYPE.ASMJS, FORMAT.CJS),
  createBrowserEntry(TARGET.BROWSER, CRYPTO_TYPE.ASMJS, FORMAT.ES),
  createBrowserEntry(TARGET.BROWSER, CRYPTO_TYPE.ASMJS, FORMAT.UMD),
  createBrowserEntry(TARGET.BROWSER, CRYPTO_TYPE.WASM, FORMAT.CJS),
  createBrowserEntry(TARGET.BROWSER, CRYPTO_TYPE.WASM, FORMAT.ES),
  createBrowserEntry(TARGET.BROWSER, CRYPTO_TYPE.WASM, FORMAT.UMD),
  createNodeJsEntry(CRYPTO_TYPE.ASMJS, FORMAT.CJS),
  createNodeJsEntry(CRYPTO_TYPE.ASMJS, FORMAT.ES),
  createNodeJsEntry(CRYPTO_TYPE.WASM, FORMAT.CJS),
  createNodeJsEntry(CRYPTO_TYPE.WASM, FORMAT.ES),
  createBrowserEntry(TARGET.WORKER, CRYPTO_TYPE.ASMJS, FORMAT.CJS),
  createBrowserEntry(TARGET.WORKER, CRYPTO_TYPE.ASMJS, FORMAT.ES),
  createBrowserEntry(TARGET.WORKER, CRYPTO_TYPE.ASMJS, FORMAT.UMD),
  createBrowserEntry(TARGET.WORKER, CRYPTO_TYPE.WASM, FORMAT.CJS),
  createBrowserEntry(TARGET.WORKER, CRYPTO_TYPE.WASM, FORMAT.ES),
  createBrowserEntry(TARGET.WORKER, CRYPTO_TYPE.WASM, FORMAT.UMD),
];
