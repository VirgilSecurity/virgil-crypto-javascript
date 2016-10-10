import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function decryptWithKey (encryptedData, recipientId, privateKey, privateKeyPassword = new Buffer(0)) {
	let virgilCipher = new VirgilCrypto.VirgilCipher();
	let decryptedDataBuffer;

	try {
		decryptedDataBuffer = byteArrayToBuffer(
			virgilCipher.decryptWithKey(
				bufferToByteArray(encryptedData),
				bufferToByteArray(recipientId),
				bufferToByteArray(privateKey),
				bufferToByteArray(privateKeyPassword))
		);

	} catch (e) {
		throwVirgilError('90002', { error: e.message });
	} finally {
		virgilCipher.delete();
	}

	return decryptedDataBuffer;
}

export default decryptWithKey;
