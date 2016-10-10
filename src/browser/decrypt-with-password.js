import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function decryptWithPassword (encryptedData, password) {
	let virgilCipher = new VirgilCrypto.VirgilCipher();
	let decryptedDataBuffer;

	try {
		decryptedDataBuffer = byteArrayToBuffer(
			virgilCipher.decryptWithPassword(
				bufferToByteArray(encryptedData),
				bufferToByteArray(password))
		);
	} catch (e) {
		throwVirgilError('90004', { error: e.message });
	} finally {
		virgilCipher.delete();
	}

	return decryptedDataBuffer;
}

export default decryptWithPassword;
