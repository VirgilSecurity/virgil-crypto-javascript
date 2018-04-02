/// <reference types="node" />
import { EncryptionKey } from 'virgil-crypto-utils';
/**
 * Encrypt data.
 *
 * @param data {Buffer} - Data to encrypt.
 * @param encryptionKey {EncryptionKey|EncryptionKey[]} - Public key with identifier or an array of
 * public keys with identifiers to encrypt with.
 *
 * @returns {Buffer} - Encrypted data.
 */
export declare function encrypt(data: Buffer, encryptionKey: EncryptionKey | EncryptionKey[]): any;
