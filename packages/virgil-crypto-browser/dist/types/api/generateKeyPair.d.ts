/// <reference types="node" />
import { KeyPairType } from 'virgil-crypto-utils';
export declare type KeyPairOptions = {
    type?: KeyPairType;
    password?: Buffer;
};
/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keypair options.
 * @param {Buffer} [options.password] - Private key password (Optional).
 * @param {string} [options.type=] - Keys type identifier (Optional).
 * 		If provided must be one of KeyPairType values.
 * @returns {{publicKey: Buffer, privateKey: Buffer}}
 */
export declare function generateKeyPair(options?: KeyPairOptions): {
    privateKey: Buffer;
    publicKey: Buffer;
};
