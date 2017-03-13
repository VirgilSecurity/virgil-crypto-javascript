import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
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

	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = bufferToByteArray(privateKeyPassword);

	try {
		return convertToBufferAndRelease(
			VirgilCrypto.VirgilKeyPair.encryptPrivateKey(
				privateKeyArr,
				passwordArr)
		);
	} catch (e) {
		throwVirgilError('90009', { error: e.message });
	} finally  {
		privateKeyArr.delete();
		passwordArr.delete();
	}
}
