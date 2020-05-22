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

const getOutputFilename = (target, cryptoType, format, extension = 'js') =>
  `${target}${cryptoType === CRYPTO_TYPE.ASMJS ? '.asmjs' : ''}.${format}.${extension}`;

const getCryptoEntryPointName = (target, cryptoType, format) => {
  const myCryptoType = cryptoType === CRYPTO_TYPE.ASMJS ? '.asmjs' : '';
  const myFormat = format === FORMAT.UMD ? 'es' : format;
  return `${target}${myCryptoType}.${myFormat}.js`;
};

module.exports = {
  FORMAT,
  CRYPTO_TYPE,
  TARGET,
  getOutputFilename,
  getCryptoEntryPointName,
};
