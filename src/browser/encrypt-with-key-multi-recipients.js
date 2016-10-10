import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function encryptWithKeyMultiRecipients (initialData, recipients) {
	const virgilCipher = new VirgilCrypto.VirgilCipher();
	let encryptedDataBuffer;

	try {
		recipients.forEach((recipient) => {
			virgilCipher.addKeyRecipient(
				bufferToByteArray(recipient.recipientId),
				bufferToByteArray(recipient.publicKey));
		});

		encryptedDataBuffer = byteArrayToBuffer(virgilCipher.encrypt(bufferToByteArray(initialData), true));
	} catch (e) {
		throwVirgilError('90008', { error: e.message });
	} finally {
		virgilCipher.delete();
	}

	return encryptedDataBuffer;
}

export default encryptWithKeyMultiRecipients;
