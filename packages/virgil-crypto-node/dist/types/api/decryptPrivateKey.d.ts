/// <reference types="node" />
/**
 * Decrypts encrypted private key.
 * @param {Buffer} privateKey - Private key to decrypt.
 * @param {Buffer} [password] - Private key password.
 *
 * @returns {Buffer} - Decrypted private key
 * */
export declare function decryptPrivateKey(privateKey: Buffer, password: Buffer): any;
