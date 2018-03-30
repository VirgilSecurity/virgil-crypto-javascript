/// <reference types="node" />
import { KeyPairType } from 'virgil-crypto-utils';
export interface IVirgilCryptoApi {
    generateKeyPair(options: {
        type?: KeyPairType;
        password?: Buffer;
    }): {
        privateKey: Buffer;
        publicKey: Buffer;
    };
    privateKeyToDer(privateKey: Buffer, password?: Buffer): Buffer;
    publicKeyToDer(publicKey: Buffer): Buffer;
    hash(data: Buffer, algorithm?: string): Buffer;
}
