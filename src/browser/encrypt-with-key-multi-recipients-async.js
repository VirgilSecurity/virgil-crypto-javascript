import browser from 'bowser';
import * as CryptoUtils from '../utils/crypto-utils';
import { createWorkerCryptoFunc } from '../utils/create-worker-crypto-func';
import { throwVirgilError } from '../utils/crypto-errors';
import { encryptWithKeyMultiRecipients } from './encrypt-with-key-multi-recipients';

export function encryptWithKeyMultiRecipientsAsync (initialData, recipients) {
	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(encryptWithKeyMultiRecipients(initialData, recipients));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(encryptWithKeyMultiRecipientsAsyncWorker);

		return worker(CryptoUtils.toBase64(initialData), recipients).then(
			// convert the base64 response to Buffer for support new interface
			(result) => CryptoUtils.base64ToBuffer(result),
			() => throwVirgilError('90008', { initialData: initialData, recipients: recipients })
		);
	}
}

function encryptWithKeyMultiRecipientsAsyncWorker (initialData, recipients) {
	let deferred = this.deferred();
	let virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	let dataByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(initialData);

	try {
		let recipientIdsByteArrays = [];

		for (let i = 0, l = recipients.length; i < l; i++) {
			var recipient = recipients[i];

			let recipientIdByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(recipient.recipientId);
			let publicKeyByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(recipient.publicKey);

			virgilCipher.addKeyRecipient(recipientIdByteArray, publicKeyByteArray);
			recipientIdsByteArrays.push(recipientIdByteArray);
		}

		let encryptedDataByteArray = virgilCipher.encrypt(dataByteArray, true);
		let encryptedDataBase64 = VirgilCryptoWorkerContext.VirgilBase64.encode(encryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		dataByteArray.delete();
		encryptedDataByteArray.delete();

		for (let j = 0, rsl = recipientIdsByteArrays.length; j < rsl; j++) {
			recipientIdsByteArrays[j].delete();
		}

		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e);
	} finally {
		virgilCipher.delete();
	}
}

export default encryptWithKeyMultiRecipientsAsync;
