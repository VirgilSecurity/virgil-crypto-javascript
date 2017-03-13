import { encryptWithPassword } from './encrypt-with-password';
import { encryptWithKey } from './encrypt-with-key';
import { encryptWithKeyMultiRecipients } from './encrypt-with-key-multi-recipients';
import { checkIsBuffer } from './utils/crypto-errors';
import { isBuffer } from './utils/crypto-utils';

/**
 * Encrypt data
 *
 * @param initialData {Buffer}
 * @param recipientId {Buffer|Array} - [{ recipientId: <Buffer>, publicKey: <Buffer> }]
 * @param [publicKey] {Buffer}
 *
 * @returns {Buffer}
 */
export function encrypt (initialData, recipientId, publicKey) {
	let encryptedData, recipients;

	checkIsBuffer(initialData, 'initialData');
	if (!Array.isArray(recipientId)) {
		checkIsBuffer(recipientId, 'recipientId');
	} else {
		recipients = recipientId;
	}



	if (recipients) {
		encryptedData = encryptWithKeyMultiRecipients(initialData, recipients);
	} else if (isBuffer(recipientId) && isBuffer(publicKey)) {
		encryptedData = encryptWithKey(initialData, recipientId, publicKey);
	} else {
		let password = recipientId;

		encryptedData = encryptWithPassword(initialData, password);
	}

	return encryptedData;
}

export default encrypt;
