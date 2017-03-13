import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease,
	stringToByteArray
} from './utils/crypto-utils';
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
	const dataArr = bufferToByteArray(data);
	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = stringToByteArray('');
	const signatureKeyArr = stringToByteArray(constants.DATA_SIGNATURE_KEY);
	const recipientsTransformed = recipients.map(r => ({
		id: bufferToByteArray(r.recipientId),
		publicKey: bufferToByteArray(r.publicKey)
	}));

	try {
		let signature = signer.sign(
			dataArr,
			privateKeyArr,
			passwordArr);

		cipher
			.customParams()
			.setData(signatureKeyArr, signature);

		recipientsTransformed.forEach(recipient =>
			cipher.addKeyRecipient(recipient.id, recipient.publicKey)
		);

		return convertToBufferAndRelease(cipher.encrypt(dataArr, true));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		signer.delete();
		cipher.delete();
		dataArr.delete();
		privateKeyArr.delete();
		passwordArr.delete();
		signatureKeyArr.delete();
		recipientsTransformed.forEach(recipient => {
			recipient.id.delete();
			recipient.publicKey.delete();
		});
	}
}

export default signThenEncrypt;

