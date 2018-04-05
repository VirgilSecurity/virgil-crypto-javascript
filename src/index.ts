import { cryptoApi } from './node/api';
import { makeVirgilCryptoFactory, VirgilCryptoOptions } from './createVirgilCrypto';
import { IVirgilCrypto } from './IVirgilCrypto';

export { KeyPairType, HashAlgorithm } from './common';
export { VirgilAccessTokenSigner } from './VirgilAccessTokenSigner';
export { VirgilPrivateKeyExporter } from './VirgilPrivateKeyExporter';
export { VirgilCardCrypto } from './VirgilCardCrypto';

export const createVirgilCrypto: (options?: VirgilCryptoOptions) => IVirgilCrypto = makeVirgilCryptoFactory(cryptoApi);
