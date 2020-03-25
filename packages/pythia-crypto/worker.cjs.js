const { initPythia } = require('./dist/worker.cjs');
const pythiaWasm = require('./dist/libpythia.worker.wasm');

const defaultOptions = {
  pythia: [{ locateFile: () => pythiaWasm }],
};

module.exports = require('./dist/worker.cjs');

module.exports.initPythia = options => initPythia(options || defaultOptions);
