const fs = require('fs');
const path = require('path');

const _ = require('lodash');

const filesPath = path.join(__dirname, 'dist');
const coreFoundationPath = path.join(__dirname, 'node_modules', '@virgilsecurity', 'core-foundation');

const wasmFilePaths = [
  path.join(coreFoundationPath, 'libfoundation.browser.wasm'),
  path.join(coreFoundationPath, 'libfoundation.worker.wasm'),
];

wasmFilePaths.forEach(wasmFilePath => {
  const dest = path.join(filesPath, path.parse(wasmFilePath).base);
  fs.copyFileSync(wasmFilePath, dest);
});

const esImport = _.template('import \'<%= path %>\';\n')
const cjsRequire = _.template('require(\'<%= path %>\');\n')

const FORMAT_CJS = 'FORMAT_CJS';
const FORMAT_ES = 'FORMAT_ES';

const files = [
  {
    format: FORMAT_CJS,
    path: path.join(filesPath, 'browser.cjs.js'),
    wasmImport: './libfoundation.browser.wasm',
  },
  {
    format: FORMAT_ES,
    path: path.join(filesPath, 'browser.es.js'),
    wasmImport: './libfoundation.browser.wasm',
  },
  {
    format: FORMAT_CJS,
    path: path.join(filesPath, 'worker.cjs.js'),
    wasmImport: './libfoundation.worker.wasm',
  },
  {
    format: FORMAT_ES,
    path: path.join(filesPath, 'worker.es.js'),
    wasmImport: './libfoundation.worker.wasm',
  },
];

files.forEach(file => {
  const contents = fs.readFileSync(file.path);
  let prepend;
  if (file.format === FORMAT_ES) {
    prepend = esImport({ path: file.wasmImport });
  } else if (file.format === FORMAT_CJS) {
    prepend = cjsRequire({ path: file.wasmImport });
  } else {
    throw new TypeError(`Unknown format '${file.format}'`);
  }
  const output = Buffer.concat([Buffer.from(prepend), contents]);
  fs.writeFileSync(file.path, output);
});
