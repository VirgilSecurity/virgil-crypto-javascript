import browser from 'bowser';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import CryptoWorkerApi from './crypto-worker-api';
import { throwVirgilError } from './utils/crypto-errors';
import { decryptWithKey } from './decrypt-with-key';

export function decryptWithKeyAsync (encryptedData, recipientId, privateKey, privateKeyPassword = new Buffer(0)) {
	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(decryptWithKey(encryptedData, recipientId, privateKey, privateKeyPassword));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi.decryptWithKey(
			toBase64(encryptedData),
			toBase64(recipientId),
			toBase64(privateKey),
			toBase64(privateKeyPassword))
		.then(base64ToBuffer)
		.catch((e) => throwVirgilError('90002', { error: e }));
	}
}

export default decryptWithKeyAsync;
