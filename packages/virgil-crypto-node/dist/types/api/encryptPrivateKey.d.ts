/// <reference types="node" />
/**
 * Encrypts the private key with password
 *
 * @param {Buffer} privateKey - Private key to encrypt
 * @param {Buffer} password - Password to encrypt the private key with
 *
 * @returns {Buffer} - Encrypted private key
 * */
export declare function encryptPrivateKey(privateKey: Buffer, password: Buffer): any;
