import browser from 'bowser';
import * as CryptoUtils from '../utils/crypto-utils';
import { createWorkerCryptoFunc } from '../utils/create-worker-crypto-func';
import { throwVirgilError } from '../utils/crypto-errors';
import { encryptWithKey } from './encrypt-with-key';

export function encryptWithKeyAsync (initialData, recipientId, publicKey) {
	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(encryptWithKey(initialData, recipientId, publicKey));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(encryptWithKeyAsyncWorker);

		return worker(CryptoUtils.toBase64(initialData), recipientId, publicKey).then(
			// convert the base64 response to Buffer for support new interface
			(result) => CryptoUtils.base64ToBuffer(result),
			() => throwVirgilError('90001', { initialData: initialData, key: publicKey })
		);
	}
}

function encryptWithKeyAsyncWorker (initialData, recipientId, publicKey) {
	let deferred = this.deferred();
	let virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();

	try {
		let recipientIdByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(recipientId);
		let dataByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(initialData);
		let publicKeyByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(publicKey);

		virgilCipher.addKeyRecipient(recipientIdByteArray, publicKeyByteArray);
		let encryptedDataByteArray = virgilCipher.encrypt(dataByteArray, true);
		let encryptedDataBase64 = VirgilCryptoWorkerContext.VirgilBase64.encode(encryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		recipientIdByteArray.delete();
		dataByteArray.delete();
		encryptedDataByteArray.delete();

		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e);
	} finally {
		virgilCipher.delete();
	}
}

export default encryptWithKeyAsync;
