import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, convertToBufferAndRelease, stringToByteArray } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';
import { makeInternalPrivateKey } from './utils/makeInternalPrivateKey';
import { makeInternalPublicKey } from './utils/makeInternalPublicKey';
import * as constants from '../lib/constants';

/**
 * An object representing a private key with metadata.
 * @typedef {Object} PrivateKey
 * @property {Buffer} privateKey
 * @property {Buffer} recipientId - Id of the key. Can be any value.
 * 		Must be the same for the public and private keys of the same pair.
 * @property {Buffer} password
 */

/**
 * An object representing a public key with an identifier.
 * @typedef {Object} PublicKey
 * @property {Buffer} publicKey
 * @property {Buffer} recipientId - Id of the key. Can be any value.
 * 		Must be the same for the public and private keys of the same pair.
 */

/**
 * Signs and encrypts the data.
 *
 * @param {Buffer} data
 * @param {Buffer|PrivateKey} privateKey - The `privateKey` can be an
 * 		object or a Buffer. If `privateKey` is a Buffer, it is treated as a
 * 		raw key without password. If it is an object, it is interpreted as a
 * 		hash containing three properties: `privateKey`, optional `recipientId`
 * 		and optional `password`.
 * @param {Buffer|PublicKey} recipientId -
 * 		Recipient ID if encrypting for single recipient OR
 * 		Array of recipientId - publicKey pairs if encrypting for multiple recipients
 * @param {Buffer} [publicKey] - Public key if encrypting for single recipient.
 * 		Ignored if encrypting for multiple recipients.
 *
 * @returns {Buffer} Signed and encrypted data.
 */
export function signThenEncrypt (data, privateKey, recipientId, publicKey) {
	checkIsBuffer(data, 'data');

	const signingKey = makeInternalPrivateKey(privateKey);
	const recipients = Array.isArray(recipientId) ?
		recipientId.map(makeInternalPublicKey) :
		[makeInternalPublicKey(publicKey, recipientId)];

	if (recipients.length === 0) {
		throwVirgilError('10000', {
			error: 'Cannot "singThenEncrypt". ' +
			'At least one recipient public key must be provided.'
		});
	}

	const signer = new VirgilCrypto.VirgilSigner();
	const cipher = new VirgilCrypto.VirgilCipher();
	const dataArr = bufferToByteArray(data);
	const signatureKey = stringToByteArray(constants.DATA_SIGNATURE_KEY);
	const signerIdKey = stringToByteArray(constants.DATA_SIGNER_ID_KEY);

	try {
		let signature = signer.sign(
			dataArr,
			signingKey.privateKey,
			signingKey.password);

		cipher
			.customParams()
			.setData(signatureKey, signature);

		if (signingKey.recipientId) {
			cipher
				.customParams()
				.setData(signerIdKey, signingKey.recipientId);
		}

		recipients.forEach(recipient =>
			cipher.addKeyRecipient(recipient.recipientId, recipient.publicKey)
		);

		return convertToBufferAndRelease(cipher.encrypt(dataArr, true));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		signer.delete();
		cipher.delete();
		dataArr.delete();
		signingKey.delete();
		signatureKey.delete();
		signerIdKey.delete();
		recipients.forEach(recipient => recipient.delete());
	}
}

export default signThenEncrypt;
