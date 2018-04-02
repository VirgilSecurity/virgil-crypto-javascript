/// <reference types="node" />
/**
 * Extracts public key out of private key.
 *
 * @param {Buffer} privateKey - Private key to extract from.
 * @param {Buffer} [password] - Private key password if private key is encrypted.
 *
 * @returns {Buffer} - Extracted public key
 * */
export declare function extractPublicKey(privateKey: Buffer, password?: Buffer): any;
