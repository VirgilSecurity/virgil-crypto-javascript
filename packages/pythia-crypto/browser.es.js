import { initPythia as rawInitPythia } from './dist/browser.es';
import pythiaWasm from './dist/libpythia.browser.wasm';

export * from './dist/browser.es';

const defaultOptions = {
  pythia: [{ locateFile: () => pythiaWasm }],
};

export const initPythia = options => rawInitPythia(options || defaultOptions);
