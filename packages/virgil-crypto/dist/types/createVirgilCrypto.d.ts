/// <reference types="node" />
import { KeyPairType } from 'virgil-crypto-utils';
import { IVirgilCryptoApi } from './IVirgilCryptoApi';
export declare type KeyPair = {
    privateKey: PrivateKey;
    publicKey: PublicKey;
};
export declare class PrivateKey {
    identifier: Buffer;
    constructor(identifier: Buffer, value: Buffer);
}
export declare class PublicKey {
    identifier: Buffer;
    value: Buffer;
    constructor(identifier: Buffer, value: Buffer);
}
export declare function createVirgilCrypto(cryptoApi: IVirgilCryptoApi): {
    generateKeys: (type?: KeyPairType | undefined) => {
        privateKey: PrivateKey;
        publicKey: PublicKey;
    };
};
