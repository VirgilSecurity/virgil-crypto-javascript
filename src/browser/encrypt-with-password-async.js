import browser from 'bowser';
import * as CryptoUtils from './utils/crypto-utils';
import { createWorkerCryptoFunc } from './utils/create-worker-crypto-func';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';
import { encryptWithPassword } from './encrypt-with-password';

export function encryptWithPasswordAsync (initialData, password = '', isEmbeddedContentInfo = true) {
	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(encryptWithPassword(initialData, password, isEmbeddedContentInfo));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(encryptWithPasswordAsyncWorker);

		return worker(CryptoUtils.toBase64(initialData), password, isEmbeddedContentInfo).then(
			// convert the base64 response to Buffer for support new interface
			(result) => CryptoUtils.base64ToBuffer(result),
			() => throwVirgilError('90003', { initialData: initialData, password: password })
		);
	}
}

function encryptWithPasswordAsyncWorker (initialData, password, isEmbeddedContentInfo) {
	let deferred = this.deferred();
	let virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();

	try {
		let dataByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(initialData);
		let passwordByteArray;

		if (password) {
			passwordByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(password);
			virgilCipher.addPasswordRecipient(passwordByteArray);
		}

		let encryptedDataByteArray = virgilCipher.encrypt(dataByteArray, isEmbeddedContentInfo);
		let encryptedDataBase64 = VirgilCryptoWorkerContext.VirgilBase64.encode(encryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		dataByteArray.delete();
		if (passwordByteArray) {
			passwordByteArray.delete();
		}

		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e);
	} finally {
		virgilCipher.delete();
	}
}

export default encryptWithPasswordAsync;
