import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer, stringToByteArray } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';
import * as constants from '../lib/constants';

/**
 * Signs and encrypts the data.
 *
 * @param {Buffer} data
 * @param {Buffer} privateKey
 * @param {Buffer|Array<{recipientId:Buffer, publicKey:Buffer}>} recipientId -
 * Recipient ID if encrypting for single recipient OR
 * Array of recipientId - publicKey pairs if encrypting for multiple recipients
 * @param {Buffer} [publicKey] - Public key if encrypting for single recipient.
 * Ignored if encrypting for multiple recipients
 *
 * @returns {Buffer} Signed and encrypted data
 */
export function signThenEncrypt (data, privateKey, recipientId, publicKey) {
	let recipients;

	if (Array.isArray(recipientId)) {
		recipients = recipientId;
	} else {
		recipients = [{
			recipientId: recipientId,
			publicKey: publicKey
		}];
	}

	checkIsBuffer(data, 'data');
	checkIsBuffer(privateKey, 'privateKey');
	recipients.forEach(function (recipient) {
		checkIsBuffer(recipient.recipientId, 'recipient.recipientId');
		checkIsBuffer(recipient.publicKey, 'recipient.publicKey');
	});

	const signer = new VirgilCrypto.VirgilSigner();
	const cipher = new VirgilCrypto.VirgilCipher();

	const dataBuf = bufferToByteArray(data);

	try {
		let signature = signer.sign(
			dataBuf,
			bufferToByteArray(privateKey),
			stringToByteArray(''));

		cipher
			.customParams()
			.setData(stringToByteArray(constants.DATA_SIGNATURE_KEY), signature);

		recipients.forEach(function (recipient) {
			cipher.addKeyRecipient(
				bufferToByteArray(recipient.recipientId),
				bufferToByteArray(recipient.publicKey));
		});

		return byteArrayToBuffer(cipher.encrypt(dataBuf, true));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		signer.delete();
		cipher.delete();
	}
}

export default signThenEncrypt;

