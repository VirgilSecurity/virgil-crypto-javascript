import browser from 'bowser';
import CryptoWorkerApi from './crypto-worker-api';
import { sign } from './sign';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import { throwVirgilError, checkIsBuffer } from './utils/crypto-errors';

/**
 * Sign the encrypted data using private key using workers
 *
 * @param data {Buffer}
 * @param privateKey {Buffer}
 * @param [privateKeyPassword] {Buffer}
 * @returns {Promise}
 */
export function signAsync (data, privateKey, privateKeyPassword = new Buffer(0)) {
	checkIsBuffer(data, 'data');
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(sign(data, privateKey, privateKeyPassword));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi.sign(
				toBase64(data),
				toBase64(privateKey),
				toBase64(privateKeyPassword))
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('90005', { error: e }));
	}
}

export default signAsync;
