import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Encrypts the private key with password
 *
 * @param {Buffer} privateKey - Private key to encrypt
 * @param {Buffer} privateKeyPassword - Password to encrypt the private key with
 *
 * @returns {Buffer} - Encrypted private key
 * */
export function encryptPrivateKey(privateKey, privateKeyPassword) {
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	try {
		return byteArrayToBuffer(
			VirgilCrypto.VirgilKeyPair.encryptPrivateKey(
				bufferToByteArray(privateKey),
				bufferToByteArray(privateKeyPassword))
		);
	} catch (e) {
		throwVirgilError('90009', { error: e.message });
	}
}
