import browser from 'bowser';
import CryptoWorkerApi from './crypto-worker-api';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';
import { encryptWithPassword } from './encrypt-with-password';

export function encryptWithPasswordAsync (initialData, password) {
	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(encryptWithPassword(initialData, password));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi.encryptWithPassword(toBase64(initialData), toBase64(password))
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('90003', { error: e }));
	}
}

export default encryptWithPasswordAsync;
