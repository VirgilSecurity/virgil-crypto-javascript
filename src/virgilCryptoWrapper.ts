// import node version, the `rollup-plugin-resolve-crypto-lib`
// will substitute this with the version appropriate for the bundle
// being generated (i.e. browser or pythia)
import { lib } from './lib/node';
import { createCryptoWrapper, IVirgilCryptoWrapper } from './common';

/**
 * @hidden
 * @type {IVirgilCryptoWrapper}
 */
export const cryptoWrapper: IVirgilCryptoWrapper = createCryptoWrapper(lib);
