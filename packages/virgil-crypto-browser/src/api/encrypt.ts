import { assert, errorFromNativeError, toArray, EncryptionKey } from 'virgil-crypto-utils';
import { lib } from '../asmjs';
import { isBuffer, wrapFunction } from '../utils';

/**
 * Encrypt data.
 *
 * @param data {Buffer} - Data to encrypt.
 * @param encryptionKey {EncryptionKey|EncryptionKey[]} - Public key with identifier or an array of
 * public keys with identifiers to encrypt with.
 *
 * @returns {Buffer} - Encrypted data.
 */
export function encrypt(data: Buffer, encryptionKey: EncryptionKey|EncryptionKey[] ) {
	const encryptionKeys = toArray(encryptionKey);
	assert(isBuffer(data), 'Cannot encrypt. `data` must be a Buffer');
	assert(encryptionKey !== undefined, 'Cannot encrypt. `encryptionKey` is required');
	assert(encryptionKeys.length > 0, 'Cannot encrypt. `encryptionKey` must not be empty');

	encryptionKeys.forEach(({ identifier, publicKey }: EncryptionKey)  => {
		assert(isBuffer(identifier), 'Cannot encrypt. Public key identifier must be a Buffer.');
		assert(isBuffer(publicKey), 'Cannot encrypt. Public key must me a Buffer');
	});

	const cipher = new lib.VirgilCipher();
	const addKeyRecipientFn = wrapFunction(cipher.addKeyRecipient, cipher);
	const encryptFn = wrapFunction(cipher.encrypt, cipher);

	try {
		encryptionKeys.forEach(({ identifier, publicKey }: EncryptionKey)  => {
			addKeyRecipientFn(identifier, publicKey);
		});
		return encryptFn(data, true);
	} catch (e) {
		throw errorFromNativeError(e);
	} finally {
		cipher.delete();
	}
}
