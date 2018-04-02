/// <reference types="node" />
/**
 * Calculates the digital signature of the given data using the given private key.
 *
 * @param data {Buffer} - Data to sign.
 * @param privateKey {Buffer} - Private key to use.
 * @param [privateKeyPassword] {Buffer} - Optional password the private key is encrypted with.
 * @returns {Buffer} - Digital signature.
 */
export declare function sign(data: Buffer, privateKey: Buffer, privateKeyPassword?: Buffer): any;
