import * as VirgilCryptoAPI from './src/browser';

export const Version = PACKAGE_VERSION;
export { Buffer as Buffer };
export const VirgilCrypto = { ...{ Buffer: Buffer }, ...VirgilCryptoAPI };
export default VirgilCrypto;
