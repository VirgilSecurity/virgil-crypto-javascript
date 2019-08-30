const fs = require('fs');
const path = require('path');

const filesPath = path.join(__dirname, 'dist');
const corePythiaPath = path.join(__dirname, 'node_modules', '@virgilsecurity', 'core-pythia');

const browserWasmFilename = 'libpythia.browser.wasm';
const workerWasmFilename = 'libpythia.worker.wasm';
const wasmFilePaths = [
  path.join(corePythiaPath, browserWasmFilename),
  path.join(corePythiaPath, workerWasmFilename),
];

wasmFilePaths.forEach(wasmFilePath => {
  const dest = path.join(filesPath, path.parse(wasmFilePath).base);
  fs.copyFileSync(wasmFilePath, dest);
});

const esImport = path => `import '${path}';\n`;
const cjsRequire = path => `require('${path}');\n`;

const FORMAT = {
  CJS: 'cjs',
  ES: 'es',
};

const files = [
  {
    format: FORMAT.CJS,
    path: path.join(filesPath, 'browser.cjs.js'),
    wasmImport: `./${browserWasmFilename}`,
  },
  {
    format: FORMAT.ES,
    path: path.join(filesPath, 'browser.es.js'),
    wasmImport: `./${browserWasmFilename}`,
  },
  {
    format: FORMAT.CJS,
    path: path.join(filesPath, 'worker.cjs.js'),
    wasmImport: `./${workerWasmFilename}`,
  },
  {
    format: FORMAT.ES,
    path: path.join(filesPath, 'worker.es.js'),
    wasmImport: `./${workerWasmFilename}`,
  },
];

files.forEach(file => {
  const contents = fs.readFileSync(file.path);
  let prepend;
  if (file.format === FORMAT.ES) {
    prepend = esImport(file.wasmImport);
  } else if (file.format === FORMAT.CJS) {
    prepend = cjsRequire(file.wasmImport);
  } else {
    throw new TypeError(`Unknown format '${file.format}'`);
  }
  const output = Buffer.concat([Buffer.from(prepend), contents]);
  fs.writeFileSync(file.path, output);
});
