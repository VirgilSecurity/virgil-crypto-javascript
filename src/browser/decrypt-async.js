import { decryptWithPasswordAsync } from './decrypt-with-password-async';
import { decryptWithKeyAsync } from './decrypt-with-key-async';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Decrypt data async
 *
 * @param encryptedData {Buffer}
 * @param recipientId {Buffer}
 * @param [privateKey] {Buffer}
 * @param [privateKeyPassword] {Buffer}
 * @returns {Promise}
 */
export function decryptAsync (encryptedData, recipientId, privateKey, privateKeyPassword) {
	checkIsBuffer(encryptedData, 'encryptedData');
	checkIsBuffer(recipientId, 'recipientId');
	privateKey && checkIsBuffer(privateKey, 'privateKey');
	privateKeyPassword && checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	let decryptedDataPromise;

	if (arguments.length === 2) {
		let password = recipientId;
		decryptedDataPromise = decryptWithPasswordAsync(encryptedData, password);
	} else {
		decryptedDataPromise = decryptWithKeyAsync(encryptedData, recipientId, privateKey, privateKeyPassword);
	}

	return decryptedDataPromise;
}

export default decryptAsync;
