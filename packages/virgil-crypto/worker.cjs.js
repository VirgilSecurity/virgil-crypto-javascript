const { initCrypto } = require('./dist/worker.cjs');
const foundationWasm = require('./dist/libfoundation.worker.wasm');

const defaultOptions = {
  foundation: [{ locateFile: () => foundationWasm }],
};

module.exports = require('./dist/worker.cjs');

module.exports.initCrypto = options => initCrypto(options || defaultOptions);
