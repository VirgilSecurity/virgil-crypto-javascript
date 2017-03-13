import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function encryptWithPassword (initialData, password) {
	const embedContentInfo = true;
	const virgilCipher = new VirgilCrypto.VirgilCipher();

	const dataArr = bufferToByteArray(initialData);
	const passwordArr = password && bufferToByteArray(password);

	try {
		if (passwordArr) {
			virgilCipher.addPasswordRecipient(passwordArr);
		}

		return convertToBufferAndRelease(
			virgilCipher.encrypt(dataArr, embedContentInfo));
	} catch (e) {
		throwVirgilError('90003', { error: e.message });
	} finally {
		virgilCipher.delete();
		dataArr.delete();
		passwordArr && passwordArr.delete();
	}
}

export default encryptWithPassword;
