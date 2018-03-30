import * as cryptoApi from 'virgil-crypto-node';
import { KeyPairType, HashAlgorithm } from 'virgil-crypto-utils';
import { createVirgilCrypto, PrivateKey, PublicKey } from './createVirgilCrypto';

export { KeyPairType, HashAlgorithm };
export const crypto = createVirgilCrypto(cryptoApi);

