import { KeyPairType, HashAlgorithm } from 'virgil-crypto-utils';
import { PrivateKey, PublicKey } from './createVirgilCrypto';
export { KeyPairType, HashAlgorithm };
export declare const crypto: {
    generateKeys: (type?: KeyPairType | undefined) => {
        privateKey: PrivateKey;
        publicKey: PublicKey;
    };
};
