import { initCrypto as rawInitCrypto } from './dist/browser.es';
import foundationWasm from './dist/libfoundation.browser.wasm';

export * from './dist/browser.es';

const defaultOptions = {
  foundation: [{ locateFile: () => foundationWasm }],
};

export const initCrypto = options => rawInitCrypto(options || defaultOptions);
