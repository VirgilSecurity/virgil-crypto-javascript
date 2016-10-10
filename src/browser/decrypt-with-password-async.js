import browser from 'bowser';
import CryptoWorkerApi from './crypto-worker-api';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';
import { decryptWithPassword } from './decrypt-with-password';

export function decryptWithPasswordAsync (encryptedData, password) {
	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(decryptWithPassword(encryptedData, password));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi.decryptWithPassword(toBase64(encryptedData), toBase64(password))
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('90004', { error: e }));
	}
}

export default decryptWithPasswordAsync;
