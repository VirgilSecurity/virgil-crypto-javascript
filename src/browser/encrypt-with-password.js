import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function encryptWithPassword (initialData, password, isEmbeddedContentInfo = true) {
	const virgilCipher = new VirgilCrypto.VirgilCipher();
	let encryptedDataBuffer;

	try {
		if (password) {
			virgilCipher.addPasswordRecipient(bufferToByteArray(password));
		}

		encryptedDataBuffer = byteArrayToBuffer(
			virgilCipher.encrypt(bufferToByteArray(initialData), isEmbeddedContentInfo));
	} catch (e) {
		throwVirgilError('90003', { error: e.message });
	} finally {
		virgilCipher.delete();
	}

	return encryptedDataBuffer;
}

export default encryptWithPassword;
