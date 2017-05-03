import browser from 'bowser';
import { toBase64, base64ToBuffer } from './utils/crypto-utils';
import CryptoWorkerApi from './crypto-worker-api';
import { throwVirgilError } from './utils/crypto-errors';
import { decryptThenVerify } from './decrypt-then-verify';
import { checkIsBuffer } from './utils/crypto-errors';
import { makeInternalPrivateKey } from './utils/makeInternalPrivateKey';
import { makeInternalPublicKey } from './utils/makeInternalPublicKey';

/**
 * Decrypts the given data with private key and verify the signature with
 * public key asynchronously (in a Web Worker if that is
 * supported, otherwise just defers the execution in a Promise).
 *
 * @param {Buffer} cipherData - Data to decrypt
 * @param {Buffer} recipientId - Recipient ID used for encryption
 * @param {Buffer|PrivateKey} privateKey - The `privateKey` can be an
 * 		object or a Buffer. If `privateKey` is a Buffer, it is treated as a
 * 		raw key without password. If it is an object, it is interpreted as a
 * 		hash containing two properties: `privateKey`, and `password`.
 * @param {Buffer|PublicKey[]} publicKey - Raw public key or an array of public
 * 		keys with identifiers to verify the signature with. If the cipher data
 * 		contains an identifier of the private key used to calculate the signature,
 * 		then the public key with that identifier from `publicKey` array will be
 * 		used to validate the signature, otherwise ANY one of the keys can validate
 * 		the signature. If the signature is not valid for ALL of the keys,
 * 		an exception is thrown.
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

		const decryptingKey = makeInternalPrivateKey(privateKey, null, recipientId);
		const verifiers = Array.isArray(publicKey) ?
			publicKey.map(makeInternalPublicKey) :
			[makeInternalPublicKey(publicKey)];

		return CryptoWorkerApi.decryptThenVerify(
			toBase64(cipherData),
			toBase64(recipientId),
			decryptingKey.marshall(),
			verifiers.map(v => v.marshall()))
			.then(base64ToBuffer)
			.catch((e) => throwVirgilError('10000', { error: e }));
	}
}

export default decryptThenVerifyAsync;

