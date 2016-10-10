import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
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

	try {
		return byteArrayToBuffer(
			VirgilCrypto.VirgilKeyPair.decryptPrivateKey(
				bufferToByteArray(privateKey),
				bufferToByteArray(privateKeyPassword))
		);
	} catch (e) {
		throwVirgilError('90010', { error: e.message });
	}
}
