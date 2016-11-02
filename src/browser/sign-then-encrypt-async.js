import browser from 'bowser';
import CryptoWorkerApi from './crypto-worker-api';
import { signThenEncrypt } from './sign-then-encrypt';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import { throwVirgilError, checkIsBuffer } from './utils/crypto-errors';

/**
 * Signs and encrypts the data asynchronously using web worker.
 *
 * @param {Buffer} data
 * @param {Buffer} privateKey
 * @param {Buffer|Array<{recipientId:Buffer, publicKey:Buffer}>} recipientId -
 * Recipient ID if encrypting for single recipient OR
 * Array of recipientId - publicKey pairs if encrypting for multiple recipients
 * @param {Buffer} [publicKey] - Public key if encrypting for single recipient.
 * Ignored if encrypting for multiple recipients
 *
 * @returns {Promise<Buffer>} Signed and encrypted data
 */
export function signThenEncryptAsync (data, privateKey, recipientId, publicKey) {
	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(signThenEncrypt(data, privateKey, recipientId, publicKey));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let recipients;

		if (Array.isArray(recipientId)) {
			recipients = recipientId;
		} else {
			recipients = [{
				recipientId: recipientId,
				publicKey: publicKey
			}];
		}

		checkIsBuffer(data, 'data');
		checkIsBuffer(privateKey, 'privateKey');
		recipients.forEach(function (recipient) {
			checkIsBuffer(recipient.recipientId, 'recipient.recipientId');
			checkIsBuffer(recipient.publicKey, 'recipient.publicKey');
		});

		let recipientsMarshalled = recipients.map(r => ({
			recipientId: toBase64(r.recipientId),
			publicKey: toBase64(r.publicKey)
		}));

		return CryptoWorkerApi.signThenEncrypt(
			toBase64(data),
			toBase64(privateKey),
			recipientsMarshalled)
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('10000', { error: e }));
	}
}

export default signThenEncryptAsync;

