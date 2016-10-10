import browser from 'bowser';
import CryptoWorkerApi from './crypto-worker-api';
import { verify } from './verify';
import { toBase64 } from './utils/crypto-utils';
import { throwVirgilError, checkIsBuffer } from './utils/crypto-errors';

/**
 * Verify signed data using public key using workers
 *
 * @param data {Buffer}
 * @param sign {Buffer}
 * @param publicKey {Buffer}
 * @returns {Promise}
 */
export function verifyAsync (data, sign, publicKey) {
	checkIsBuffer(data, 'data');
	checkIsBuffer(sign, 'sign');
	checkIsBuffer(publicKey, 'publicKey');

	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(verify(data, sign, publicKey));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi.verify(toBase64(data), toBase64(sign), toBase64(publicKey))
			.catch((e) => {
				throwVirgilError('90006', { error: e });
			});
	}
}

export default verifyAsync;
