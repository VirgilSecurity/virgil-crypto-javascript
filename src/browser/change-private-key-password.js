import VirgilCrypto from './utils/crypto-module';
import { byteArrayToBuffer, bufferToByteArray } from './utils/crypto-utils';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Changes the password private key is encrypted with
 * @param {Buffer} privateKey - Private key to change password on
 * @param {Buffer} oldPassword - Old password
 * @param {Buffer} newPassword - New password
 *
 * @returns {Buffer} - Private key
 * */
export function changePrivateKeyPassword (privateKey, oldPassword, newPassword) {
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(oldPassword, 'oldPassword');
	checkIsBuffer(newPassword, 'newPassword');

	return byteArrayToBuffer(VirgilCrypto.VirgilKeyPair.resetPrivateKeyPassword(
		bufferToByteArray(privateKey),
		bufferToByteArray(oldPassword),
		bufferToByteArray(newPassword)
	));
}
