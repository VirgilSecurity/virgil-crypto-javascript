import browser from 'bowser';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import CryptoWorkerApi from './crypto-worker-api';
import { throwVirgilError } from './utils/crypto-errors';
import { decryptThenVerify } from './decrypt-then-verify';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Decrypts the given data with private key and verifies the signature with public key
 *
 * @param {Buffer} cipherData - Data to decrypt
 * @param {Buffer} recipientId - Recipient ID used for encryption
 * @param {Buffer} privateKey - Private key
 * @param {Buffer} publicKey - Public key to validate the signature with
 *
 * @returns {Promise<Buffer>} Decrypted data
 * */
export function decryptThenVerifyAsync (cipherData, recipientId, privateKey, publicKey) {
	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(decryptThenVerify(cipherData, recipientId, privateKey, publicKey));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		checkIsBuffer(cipherData, 'cipherData');
		checkIsBuffer(recipientId, 'recipientId');
		checkIsBuffer(privateKey, 'privateKey');
		checkIsBuffer(publicKey, 'publicKey');

		return CryptoWorkerApi.decryptThenVerify(
			toBase64(cipherData),
			toBase64(recipientId),
			toBase64(privateKey),
			toBase64(publicKey))
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('10000', { error: e }));
	}
}

export default decryptThenVerifyAsync;

