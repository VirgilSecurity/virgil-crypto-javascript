import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease
} from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Decrypts encrypted private key.
 * @param {Buffer} privateKey - Private key to decrypt
 * @param {Buffer} [privateKeyPassword] - Private key password
 *
 * @returns {Buffer} - Decrypted private key
* */
export function decryptPrivateKey(privateKey, privateKeyPassword) {
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = bufferToByteArray(privateKeyPassword);

	try {
		return convertToBufferAndRelease(
			VirgilCrypto.VirgilKeyPair.decryptPrivateKey(
				privateKeyArr,
				passwordArr)
		);
	} catch (e) {
		throwVirgilError('90010', { error: e.message });
	} finally {
		privateKeyArr.delete();
		passwordArr.delete();
	}
}
