import { encryptWithPassword } from './encrypt-with-password';
import { encryptWithKey } from './encrypt-with-key';
import { encryptWithKeyMultiRecipients } from './encrypt-with-key-multi-recipients';
import { checkIsBuffer } from './utils/crypto-errors';

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
	} else if (Buffer.isBuffer(recipientId) && Buffer.isBuffer(publicKey)) {
		encryptedData = encryptWithKey(initialData, recipientId, publicKey);
	} else {
		let password = recipientId;
		let isEmbeddedContentInfo = publicKey;

		encryptedData = encryptWithPassword(initialData, password, isEmbeddedContentInfo);
	}

	return encryptedData;
}

export default encrypt;
