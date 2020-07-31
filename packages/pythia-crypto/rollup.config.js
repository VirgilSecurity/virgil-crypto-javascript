const path = require('path');

const builtinModules = require('builtin-modules');
const commonjs = require('rollup-plugin-commonjs');
const copy = require('rollup-plugin-copy');
const nodeResolve = require('rollup-plugin-node-resolve');
const replace = require('rollup-plugin-re');
const { terser } = require('rollup-plugin-terser');
const typescript = require('rollup-plugin-typescript2');

const packageJson = require('./package.json');
const { createDeclarationForInnerEntry } = require('../../utils/rollup-common-configs');
const {
  FORMAT,
  CRYPTO_TYPE,
  TARGET,
  getOutputFilename,
  getCryptoEntryPointName,
} = require('../../utils/build');

const sourceDir = path.join(__dirname, 'src');
const outputDir = path.join(__dirname, 'dist');
const corePythiaDir = path.parse(require.resolve('@virgilsecurity/core-pythia')).dir;

const createBrowserEntry = (target, cryptoType, format, declaration = false) => {
  const pythiaEntryPoint = path.join(
    '@virgilsecurity',
    'core-pythia',
    getCryptoEntryPointName(target, cryptoType, format),
  );
  return {
    input: path.join(sourceDir, 'index.ts'),
    output: {
      format,
      file: path.join(outputDir, getOutputFilename(target, cryptoType, format)),
      name: 'VirgilPythiaCrypto',
    },
    external:
      format !== FORMAT.ES &&
      format !== FORMAT.UMD &&
      Object.keys(packageJson.dependencies).concat([pythiaEntryPoint]),
    plugins: [
      replace({
        patterns: [
          {
            match: /(initPythia|types)\.ts$/,
            test: '@virgilsecurity/core-pythia',
            replace: pythiaEntryPoint,
          },
        ],
      }),
      nodeResolve({ browser: true, extensions: ['.js', '.ts'] }),
      commonjs(),
      typescript({
        objectHashIgnoreUnknownHack: true,
        useTsconfigDeclarationDir: true,
        tsconfigOverride: {
          compilerOptions: {
            declaration,
          },
          exclude: [outputDir, '**/*.test.ts'],
        },
      }),
      createDeclarationForInnerEntry(target, cryptoType, format, outputDir),
      cryptoType === CRYPTO_TYPE.WASM &&
        copy({
          targets: [
            {
              src: path.join(corePythiaDir, `libpythia.${target}.wasm`),
              dest: outputDir,
            },
          ],
        }),
      (format === FORMAT.ES || format === FORMAT.UMD) && terser(),
    ],
  };
};

const createNodeJsEntry = (cryptoType, format) => {
  const pythiaEntryPoint = path.join(
    '@virgilsecurity',
    'core-pythia',
    getCryptoEntryPointName(TARGET.NODE, cryptoType, format),
  );
  const extension = format === FORMAT.ES ? 'mjs' : 'js';

  return {
    input: path.join(sourceDir, 'index.ts'),
    output: {
      format,
      file: path.join(outputDir, getOutputFilename(TARGET.NODE, cryptoType, format, extension)),
    },
    external: builtinModules
      .concat(Object.keys(packageJson.dependencies))
      .concat([pythiaEntryPoint]),
    plugins: [
      replace({
        patterns: [
          {
            match: /(initPythia|types)\.ts$/,
            test: '@virgilsecurity/core-pythia',
            replace: pythiaEntryPoint,
          },
        ],
      }),
      nodeResolve({ extensions: ['.js', '.ts'] }),
      commonjs(),
      typescript({
        objectHashIgnoreUnknownHack: true,
        useTsconfigDeclarationDir: true,
        tsconfigOverride: {
          compilerOptions: {
            declaration: false,
          },
          exclude: [outputDir, '**/*.test.ts'],
        },
      }),
      createDeclarationForInnerEntry(TARGET.NODE, cryptoType, format, outputDir),
    ],
  };
};

module.exports = [
  createBrowserEntry(TARGET.BROWSER, CRYPTO_TYPE.ASMJS, FORMAT.CJS, true),
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
