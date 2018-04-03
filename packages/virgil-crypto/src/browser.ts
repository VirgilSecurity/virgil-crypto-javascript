import { cryptoApi } from './browser/api';
import { KeyPairType, HashAlgorithm } from './common';
import { createVirgilCrypto, PrivateKey, PublicKey } from './createVirgilCrypto';

export { KeyPairType, HashAlgorithm };
export const crypto = createVirgilCrypto(cryptoApi);

