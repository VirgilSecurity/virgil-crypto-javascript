/// <reference types="node" />
import { KeyPairType, HashAlgorithm } from 'virgil-crypto-utils';
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
    importPrivateKey: (rawPrivateKey: string | Buffer, password?: string | undefined) => PrivateKey;
    importPublicKey: (rawPublicKey: string | Buffer) => PublicKey;
    exportPrivateKey: (privateKey: PrivateKey, password?: string | undefined) => any;
    exportPublicKey: (publicKey: PublicKey) => Buffer;
    extractPublicKey: (privateKey: PrivateKey) => PublicKey;
    encrypt: (data: string | Buffer, publicKey: PublicKey | PublicKey[]) => Buffer;
    decrypt: (encryptedData: string | Buffer, privateKey: PrivateKey) => Buffer;
    calculateSignature: (data: string | Buffer, privateKey: PrivateKey) => Buffer;
    verifySignature: (data: string | Buffer, signature: string | Buffer, publicKey: PublicKey) => boolean;
    calculateHash: (data: string | Buffer, algorithm?: HashAlgorithm) => Buffer;
};
