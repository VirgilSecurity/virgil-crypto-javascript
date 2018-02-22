import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { throwVirgilError } from './utils/crypto-errors';

export function encryptWithKeyMultiRecipients (initialData, recipients) {
	if (recipients.length === 0) {
		throwVirgilError('10000', {
			error: 'Cannot encrypt data, "recipients" array is empty.'
		});
	}

	const virgilCipher = new VirgilCrypto.VirgilCipher();
	const dataArr = bufferToByteArray(initialData);
	const transformedRecipients = recipients.map(recipient => ({
		recipientId: bufferToByteArray(recipient.recipientId),
		publicKey: bufferToByteArray(recipient.publicKey)
	}));

	try {
		transformedRecipients.forEach(recipient => {
			virgilCipher.addKeyRecipient(
				recipient.recipientId,
				recipient.publicKey);
		});

		return convertToBufferAndRelease(virgilCipher.encrypt(dataArr, true));
	} catch (e) {
		throwVirgilError('90008', { error: e.message });
	} finally {
		virgilCipher.delete();
		dataArr.delete();
		transformedRecipients.forEach(recipient => {
			recipient.recipientId.delete();
			recipient.publicKey.delete();
		});
	}
}

export default encryptWithKeyMultiRecipients;
