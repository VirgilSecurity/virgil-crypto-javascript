/// <reference types="node" />
/**
 * Verifies digital signature of the given data for the given public key.
 *
 * @param data {Buffer} - Data to verify.
 * @param signature {Buffer} - The signature.
 * @param publicKey {Buffer} - The public key.
 *
 * @returns {boolean} - True if signature is valid for the given public key and data,
 * otherwise False.
 */
export declare function verify(data: Buffer, signature: Buffer, publicKey: Buffer): any;
