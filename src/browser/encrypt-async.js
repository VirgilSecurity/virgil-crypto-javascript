import { encryptWithPasswordAsync } from './encrypt-with-password-async';
import { encryptWithKeyAsync } from './encrypt-with-key-async';
import { encryptWithKeyMultiRecipientsAsync } from './encrypt-with-key-multi-recipients-async';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Encrypt data async
 *
 * @param initialData {Buffer}
 * @param recipientId {Buffer|Array}
 * @param [publicKey] {Buffer}
 *
 * @returns {Promise}
 */
export function encryptAsync (initialData, recipientId, publicKey) {
	let encryptedDataPromise, recipients;

	checkIsBuffer(initialData, 'initialData');
	if (!Array.isArray(recipientId)) {
		checkIsBuffer(recipientId, 'recipientId');
	} else {
		recipients = recipientId;
	}

	if (recipients) {
		encryptedDataPromise = encryptWithKeyMultiRecipientsAsync(initialData, recipients);
	} else if (Buffer.isBuffer(recipientId) && Buffer.isBuffer(publicKey)) {
		encryptedDataPromise = encryptWithKeyAsync(initialData, recipientId, publicKey);
	} else {
		let password = recipientId;
		let isEmbeddedContentInfo = publicKey;

		encryptedDataPromise = encryptWithPasswordAsync(initialData, password, isEmbeddedContentInfo);
	}

	return encryptedDataPromise;
}

export default encryptAsync;
