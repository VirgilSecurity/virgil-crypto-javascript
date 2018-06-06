import { makeVirgilCryptoFactory } from './makeVirgilCryptoFactory';
import { cryptoApi } from './pythia/node/api';
import { VirgilCryptoFactory } from './interfaces';

export { KeyPairType, HashAlgorithm } from './common';
export { VirgilAccessTokenSigner } from './VirgilAccessTokenSigner';
export { VirgilPrivateKeyExporter } from './VirgilPrivateKeyExporter';
export { VirgilCardCrypto } from './VirgilCardCrypto';

export const createVirgilCrypto: VirgilCryptoFactory = makeVirgilCryptoFactory(cryptoApi);
export { VirgilPythia } from './VirgilPythia';
