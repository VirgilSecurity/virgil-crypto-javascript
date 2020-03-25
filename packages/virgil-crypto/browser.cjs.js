const { initCrypto } = require('./dist/browser.cjs');
const foundationWasm = require('./dist/libfoundation.browser.wasm');

const defaultOptions = {
  foundation: [{ locateFile: () => foundationWasm }],
};

module.exports = require('./dist/browser.cjs');

module.exports.initCrypto = options => initCrypto(options || defaultOptions);
