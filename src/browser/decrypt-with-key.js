import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function decryptWithKey (
	encryptedData,
	recipientId,
	privateKey,
	privateKeyPassword = new Buffer(0)) {

	const virgilCipher = new VirgilCrypto.VirgilCipher();

	const encryptedDataArr = bufferToByteArray(encryptedData);
	const recipientIdArr = bufferToByteArray(recipientId);
	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = bufferToByteArray(privateKeyPassword);

	try {
		return convertToBufferAndRelease(
			virgilCipher.decryptWithKey(
				encryptedDataArr,
				recipientIdArr,
				privateKeyArr,
				passwordArr)
		);

	} catch (e) {
		throwVirgilError('90002', { error: e.message });
	} finally {
		virgilCipher.delete();
		encryptedDataArr.delete();
		recipientIdArr.delete();
		privateKeyArr.delete();
		passwordArr.delete();
	}
}

export default decryptWithKey;
