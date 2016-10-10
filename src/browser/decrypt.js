import { decryptWithPassword } from './decrypt-with-password';
import { decryptWithKey } from './decrypt-with-key';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Decrypt data
 *
 * @param encryptedData {Buffer}
 * @param recipientId {Buffer}
 * @param [privateKey] {Buffer}
 * @param [privateKeyPassword] {Buffer}
 * @returns {Buffer}
 */
export function decrypt (encryptedData, recipientId, privateKey, privateKeyPassword) {
	checkIsBuffer(encryptedData, 'encryptedData');
	checkIsBuffer(recipientId, 'recipientId');
	privateKey && checkIsBuffer(privateKey, 'privateKey');
	privateKeyPassword && checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	let decryptedData;

	if (arguments.length === 2) {
		let password = recipientId;

		decryptedData = decryptWithPassword(encryptedData, password);
	} else {
		decryptedData = decryptWithKey(encryptedData, recipientId, privateKey, privateKeyPassword);
	}

	return decryptedData;
}

export default decrypt;
