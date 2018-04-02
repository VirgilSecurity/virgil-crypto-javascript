/// <reference types="node" />
import { KeyPairType, HashAlgorithm } from 'virgil-crypto-utils';
import { PrivateKey, PublicKey } from './createVirgilCrypto';
export { KeyPairType, HashAlgorithm };
export declare const crypto: {
    generateKeys: (type?: KeyPairType | undefined) => {
        privateKey: PrivateKey;
        publicKey: PublicKey;
    };
    encrypt: (data: string | Buffer, publicKey: PublicKey | PublicKey[]) => Buffer;
    decrypt: (encryptedData: string | Buffer, privateKey: PrivateKey) => Buffer;
};
