const { initPythia } = require('./dist/browser.cjs');
const pythiaWasm = require('./dist/libpythia.browser.wasm');

const defaultOptions = {
  foundation: [{ locateFile: () => pythiaWasm }],
};

module.exports = require('./dist/browser.cjs');

module.exports.initPythia = options => initPythia(options || defaultOptions);
