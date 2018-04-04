import { cryptoApi } from './node/api';
import { KeyPairType, HashAlgorithm } from './common';
import { createVirgilCrypto, PublicKey, PrivateKey } from './createVirgilCrypto';

export { KeyPairType, HashAlgorithm };
export const crypto = createVirgilCrypto(cryptoApi);
