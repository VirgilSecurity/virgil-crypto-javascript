import * as cryptoApi from 'virgil-crypto-browser';
import { KeyPairType, HashAlgorithm } from 'virgil-crypto-utils';
import { createVirgilCrypto, PrivateKey, PublicKey } from './createVirgilCrypto';

export { KeyPairType, HashAlgorithm };
export const crypto = createVirgilCrypto(cryptoApi);

