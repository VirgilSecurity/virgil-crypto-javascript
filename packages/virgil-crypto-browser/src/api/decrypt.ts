import { assert, errorFromNativeError, DecryptionKey } from 'virgil-crypto-utils';
import { lib } from '../asmjs';
import { isBuffer, wrapFunction } from '../utils';

/**
 * Decrypt data
 *
 * @param encryptedData {Buffer} - The data to decrypt.
 * @param decryptionKey {DecryptionKey} - Private key with identifier and optional password.
 * @returns {Buffer} - Decrypted data.
 */
export function decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey) {
	assert(isBuffer(encryptedData), 'Cannot decrypt. `encryptedData` must be a Buffer');
	assert(decryptionKey !== undefined, 'Cannot decrypt. `decryptionKey` is required');
	const { identifier, privateKey, privateKeyPassword = new Buffer(0) } = decryptionKey;
	assert(
		isBuffer(identifier) &&
		isBuffer(privateKey) &&
		(privateKeyPassword === undefined || isBuffer(privateKeyPassword)),
		'Cannot decrypt. `decryptionKey` is invalid'
	);

	const cipher = new lib.VirgilCipher();
	const decryptWithKeyFn = wrapFunction(cipher.decryptWithKey, cipher);

	try {
		return decryptWithKeyFn(encryptedData, identifier, privateKey, privateKeyPassword);
	} catch (e) {
		throw errorFromNativeError(e);
	} finally {
		cipher.delete();
	}
}
