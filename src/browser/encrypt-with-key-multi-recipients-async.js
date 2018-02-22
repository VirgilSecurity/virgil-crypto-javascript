import browser from 'bowser';
import CryptoWorkerApi from './crypto-worker-api';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';
import { encryptWithKeyMultiRecipients } from './encrypt-with-key-multi-recipients';

export function encryptWithKeyMultiRecipientsAsync (initialData, recipients) {
	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(encryptWithKeyMultiRecipients(initialData, recipients));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		if (recipients.length === 0) {
			throwVirgilError('10000', {
				error: 'Cannot encrypt data, "recipients" array is empty.'
			});
		}

		recipients = recipients.map((r) => {
			return {
				recipientId: toBase64(r.recipientId),
				publicKey: toBase64(r.publicKey )
			};
		});
		return CryptoWorkerApi.encryptWithKeyMultiRecipients(toBase64(initialData), recipients)
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('90008', { error: e }));
	}
}

export default encryptWithKeyMultiRecipientsAsync;
