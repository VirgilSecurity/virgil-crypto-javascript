/// <reference types="node" />
import { DecryptionKey } from 'virgil-crypto-utils';
/**
 * Decrypt data
 *
 * @param encryptedData {Buffer} - The data to decrypt.
 * @param decryptionKey {DecryptionKey} - Private key with identifier and optional password.
 * @returns {Buffer} - Decrypted data.
 */
export declare function decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey): any;
