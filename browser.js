import * as VirgilCryptoAPI from './src/browser';

export { Buffer } from 'buffer';
export const Version = PACKAGE_VERSION;
export const VirgilCrypto = { ...{ Buffer: Buffer }, ...VirgilCryptoAPI };
