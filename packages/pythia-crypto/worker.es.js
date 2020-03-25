import { initPythia as rawInitPythia } from './dist/worker.es';
import pythiaWasm from './dist/libpythia.worker.wasm';

export * from './dist/worker.es';

const defaultOptions = {
  pythia: [{ locateFile: () => pythiaWasm }],
};

export const initPythia = options => rawInitPythia(options || defaultOptions);
