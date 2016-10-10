import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function encryptWithKey (initialData, recipientId, publicKey) {
	const virgilCipher = new VirgilCrypto.VirgilCipher();
	let encryptedDataBuffer;

	try {
		virgilCipher.addKeyRecipient(bufferToByteArray(recipientId), bufferToByteArray(publicKey));
		encryptedDataBuffer = byteArrayToBuffer(virgilCipher.encrypt(bufferToByteArray(initialData), true));

	} catch (e) {
		throwVirgilError('90001', { error: e.message });
	} finally {
		virgilCipher.delete();
	}

	return encryptedDataBuffer;
}

export default encryptWithKey;
