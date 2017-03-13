import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function decryptWithPassword (encryptedData, password) {
	const virgilCipher = new VirgilCrypto.VirgilCipher();
	const encryptedDataArr = bufferToByteArray(encryptedData);
	const passwordArr = bufferToByteArray(password);

	try {
		return convertToBufferAndRelease(
			virgilCipher.decryptWithPassword(
				encryptedDataArr,
				passwordArr)
		);
	} catch (e) {
		throwVirgilError('90004', { error: e.message });
	} finally {
		virgilCipher.delete();
		encryptedDataArr.delete();
		passwordArr.delete();
	}
}

export default decryptWithPassword;
