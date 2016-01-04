import browser from 'bowser';
import * as CryptoUtils from '../utils/crypto-utils';
import { createWorkerCryptoFunc } from '../utils/create-worker-crypto-func';
import { throwVirgilError } from '../utils/crypto-errors';
import { decryptWithKey } from './decrypt-with-key';

export function decryptWithKeyAsync (initialEncryptedData, recipientId, privateKey, privateKeyPassword) {
	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(decryptWithKey(initialEncryptedData, recipientId, privateKey, privateKeyPassword));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(decryptWithKeyAsyncWorker);

		return worker(CryptoUtils.toBase64(initialEncryptedData), recipientId, CryptoUtils.toBase64(privateKey), privateKeyPassword).then(
			// convert the base64 response to Buffer for support new interface
			(result) => CryptoUtils.base64ToBuffer(result),
			() => throwVirgilError('90002', { initialData: initialEncryptedData, key: privateKey })
		);
	}
}

function decryptWithKeyAsyncWorker (initialEncryptedData, recipientId, privateKeyBase64, privateKeyPassword) {
	let deferred = this.deferred();
	let virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();

	try {
		let recipientIdByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(recipientId);
		let dataByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(initialEncryptedData);
		let privateKeyByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(privateKeyBase64);
		let privateKeyPasswordByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(privateKeyPassword);
		let decryptedDataByteArray = virgilCipher.decryptWithKey(dataByteArray, recipientIdByteArray, privateKeyByteArray, privateKeyPasswordByteArray);
		let decryptedDataBase64 = VirgilCryptoWorkerContext.VirgilBase64.encode(decryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		recipientIdByteArray.delete();
		dataByteArray.delete();
		privateKeyByteArray.delete();
		decryptedDataByteArray.delete();
		privateKeyPasswordByteArray.delete();

		deferred.resolve(decryptedDataBase64);
	} catch (e) {
		deferred.reject(e);
	} finally {
		virgilCipher.delete();
	}
}

export default decryptWithKeyAsync;
