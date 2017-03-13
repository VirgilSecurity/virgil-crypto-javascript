import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function encryptWithKey (initialData, recipientId, publicKey) {
	const virgilCipher = new VirgilCrypto.VirgilCipher();
	const dataArr = bufferToByteArray(initialData);
	const recipientIdArr = bufferToByteArray(recipientId);
	const publicKeyArr = bufferToByteArray(publicKey)

	try {
		virgilCipher.addKeyRecipient(recipientIdArr, publicKeyArr);
		return convertToBufferAndRelease(virgilCipher.encrypt(dataArr, true));
	} catch (e) {
		throwVirgilError('90001', { error: e.message });
	} finally {
		virgilCipher.delete();
		dataArr.delete();
		recipientIdArr.delete();
		publicKeyArr.delete();
	}
}

export default encryptWithKey;
