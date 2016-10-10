import browser from 'bowser';
import CryptoWorkerApi from './crypto-worker-api';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';
import { encryptWithKey } from './encrypt-with-key';

export function encryptWithKeyAsync (initialData, recipientId, publicKey) {
	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(encryptWithKey(initialData, recipientId, publicKey));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi
			.encryptWithKey(toBase64(initialData), toBase64(recipientId), toBase64(publicKey))
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('90001', { error: e }));
	}
}

export default encryptWithKeyAsync;
