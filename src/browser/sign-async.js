import _ from 'lodash';
export { Buffer } from 'buffer';
import browser from 'bowser';
import * as CryptoUtils from './utils/crypto-utils';
import { createWorkerCryptoFunc } from './utils/create-worker-crypto-func';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';
import { sign } from './sign';

/**
 * Sign the encrypted data using private key using workers
 *
 * @param data {string|Buffer}
 * @param privateKey {string}
 * @param [privateKeyPassword = ''] {string}
 * @returns {Promise}
 */
export function signAsync (data, privateKey, privateKeyPassword = '') {
	if (!(_.isString(data) || Buffer.isBuffer(data))) {
		throwValidationError('00001', { arg: 'data', type: 'String or Buffer' });
	}

	if (!_.isString(privateKey)) {
		throwValidationError('00001', { arg: 'privateKey', type: 'String' });
	}

	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(sign(data, privateKey, privateKeyPassword));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(signAsyncWorker);

		return worker(CryptoUtils.toBase64(data), CryptoUtils.toBase64(privateKey), privateKeyPassword).then(
			// convert the base64 response to Buffer for support new interface
			(result) => CryptoUtils.base64ToBuffer(result),
			() => throwVirgilError('90005', { initialData: data, key: privateKey, password: privateKeyPassword })
		);
	}
}

function signAsyncWorker (initialData, privateKeyBase64, privateKeyPassword) {
	let deferred = this.deferred();
	let virgilSigner = new VirgilCryptoWorkerContext.VirgilSigner();

	try {
		let dataByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(initialData);
		let privateKeyByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(privateKeyBase64);
		let privateKeyPasswordByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(privateKeyPassword);

		let sign = virgilSigner.sign(dataByteArray, privateKeyByteArray, privateKeyPasswordByteArray);
		let signBase64 = VirgilCryptoWorkerContext.VirgilBase64.encode(sign);

		// cleanup memory to avoid memory leaks
		dataByteArray.delete();
		privateKeyByteArray.delete();
		privateKeyPasswordByteArray.delete();

		deferred.resolve(signBase64);
	} catch (e) {
		deferred.reject(e);
	} finally {
		virgilSigner.delete();
	}
}

export default signAsync;
