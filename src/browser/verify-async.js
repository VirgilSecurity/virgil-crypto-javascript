import _ from 'lodash';
import browser from 'bowser';
import * as CryptoUtils from './utils/crypto-utils';
import { createWorkerCryptoFunc } from './utils/create-worker-crypto-func';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';
import verify from './verify';

/**
 * Verify signed data using public key using workers
 *
 * @param data {string|Buffer}
 * @param publicKey {string}
 * @param sign {Buffer}
 * @returns {Promise}
 */
export function verifyAsync (data, publicKey, sign) {
	if (!(_.isString(data) || Buffer.isBuffer(data))) {
		throwValidationError('00001', { arg: 'data', type: 'String or Buffer' });
	}

	if (!_.isString(publicKey)) {
		throwValidationError('00001', { arg: 'publicKey', type: 'String' });
	}

	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(verify(data, publicKey, sign));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(verifyAsyncWorker);

		return worker(CryptoUtils.toBase64(data), publicKey, CryptoUtils.toBase64(sign)).catch(() => {
			throwVirgilError('90006', { initialData: data, key: publicKey, sign: sign });
		});
	}
}

// module functions
function verifyAsyncWorker (initialData, publicKey, sign) {
	let deferred = this.deferred();
	let virgilSigner = new VirgilCryptoWorkerContext.VirgilSigner();

	try {
		let signByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(sign);
		let dataByteArray = VirgilCryptoWorkerContext.VirgilBase64.decode(initialData);
		let publicKeyByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(publicKey);
		let isVerified = virgilSigner.verify(dataByteArray, signByteArray, publicKeyByteArray);

		// cleanup memory to avoid memory leaks
		dataByteArray.delete();
		publicKeyByteArray.delete();
		signByteArray.delete();

		deferred.resolve(isVerified);
	} catch (e) {
		deferred.reject(e);
	} finally {
		virgilSigner.delete();
	}
}

export default verifyAsync;
