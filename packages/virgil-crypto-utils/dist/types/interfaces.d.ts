/// <reference types="node" />
export declare type EncryptionKey = {
    identifier: Buffer;
    publicKey: Buffer;
};
export declare type DecryptionKey = {
    identifier: Buffer;
    privateKey: Buffer;
    privateKeyPassword?: Buffer;
};
