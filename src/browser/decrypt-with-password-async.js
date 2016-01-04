import browser from 'bowser';
import * as CryptoUtils from '../utils/crypto-utils';
import { createWorkerCryptoFunc } from '../utils/create-worker-crypto-func';
import { throwVirgilError } from '../utils/crypto-errors';
import { decryptWithPassword } from './decrypt-with-password';

export function decryptWithPasswordAsync (initialEncryptedData, password = '') {
	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(decryptWithPassword(initialEncryptedData, password));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(decryptWithPasswordAsyncWorker);

		return worker(CryptoUtils.toBase64(initialEncryptedData), password).then(
			// convert the base64 response to Buffer for support new interface
			(result) => CryptoUtils.base64ToBuffer(result),
			() => throwVirgilError('90004', { initialData: initialEncryptedData, password: password })
		);
	}
}

function decryptWithPasswordAsyncWorker (initialEncryptedData, password) {
	let deferred = this.deferred();
	let virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();

	try {
		let dataByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(initialEncryptedData);
		let passwordByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(password);
		let decryptedDataByteArray = virgilCipher.decryptWithPassword(dataByteArray, passwordByteArray);
		let decryptedData = VirgilCryptoWorkerContext.VirgilBase64.encode(decryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		dataByteArray.delete();
		passwordByteArray.delete();
		decryptedDataByteArray.delete();

		deferred.resolve(decryptedData);
	} catch (e) {
		deferred.reject(e);
	} finally {
		virgilCipher.delete();
	}
}

export default decryptWithPasswordAsync;
