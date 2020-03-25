import { initCrypto as rawInitCrypto } from './dist/worker.es';
import foundationWasm from './dist/libfoundation.worker.wasm';

export * from './dist/worker.es';

const defaultOptions = {
  foundation: [{ locateFile: () => foundationWasm }],
};

export const initCrypto = options => rawInitCrypto(options || defaultOptions);
