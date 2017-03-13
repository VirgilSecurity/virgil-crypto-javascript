import VirgilCrypto from './utils/crypto-module';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';
import {
	bufferToByteArray,
	convertToBufferAndRelease
} from './utils/crypto-utils';

/**
 * Changes the password private key is encrypted with
 * @param {Buffer} privateKey - Private key to change password on
 * @param {Buffer} oldPassword - Old password
 * @param {Buffer} newPassword - New password
 *
 * @returns {Buffer} - Private key
 * */
export function changePrivateKeyPassword (
	privateKey, oldPassword, newPassword) {

	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(oldPassword, 'oldPassword');
	checkIsBuffer(newPassword, 'newPassword');

	const privateKeyArr = bufferToByteArray(privateKey);
	const oldPasswordArr = bufferToByteArray(oldPassword);
	const newPasswordArr = bufferToByteArray(newPassword);

	try {
		return convertToBufferAndRelease(
			VirgilCrypto.VirgilKeyPair.resetPrivateKeyPassword(
				privateKeyArr,
				oldPasswordArr,
				newPasswordArr)
		);
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		privateKeyArr.delete();
		oldPasswordArr.delete();
		newPasswordArr.delete();
	}
}
