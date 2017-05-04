var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');
var makePrivateKey = require('./helpers/makePrivateKey');
var makePublicKey = require('./helpers/makePublicKey');
var VirgilCryptoError = require('./virgil-crypto-error');
var constants = require('../lib/constants');

/**
 * An object representing a private key with metadata.
 * @typedef {Object} PrivateKeyInfo
 * @property {Buffer} privateKey
 * @property {Buffer} recipientId - Id of the key. Can be any value.
 * 		Must be the same for the public and private keys of the same pair.
 * @property {Buffer} password
 */

/**
 * An object representing a public key with an identifier.
 * @typedef {Object} PublicKeyInfo
 * @property {Buffer} publicKey
 * @property {Buffer} recipientId - Id of the key. Can be any value.
 * 		Must be the same for the public and private keys of the same pair.
 */

/**
 * Signs and encrypts the data.
 *
 * @param {Buffer} data
 * @param {Buffer|PrivateKeyInfo} privateKey - The `privateKey` can be an
 * 		object or a Buffer. If `privateKey` is a Buffer, it is treated as a
 * 		raw key without password. If it is an object, it is interpreted as a
 * 		hash containing three properties: `privateKey`, optional `recipientId`
 * 		and optional `password`.
 * @param {Buffer|PublicKeyInfo} recipientId -
 * 		Recipient ID if encrypting for single recipient OR
 * 		Array of recipientId - publicKey pairs if encrypting for multiple recipients
 * @param {Buffer} [publicKey] - Public key if encrypting for single recipient.
 * 		Ignored if encrypting for multiple recipients.
 *
 * @returns {Buffer} Signed and encrypted data.
 */
module.exports = function signThenEncrypt (data, privateKey, recipientId, publicKey) {
	u.checkIsBuffer(data, 'data');

	var signingKey = makePrivateKey(privateKey);

	var recipients = Array.isArray(recipientId) ?
		recipientId.map(function (publicKey) {
			// don't pass `makePublicKey` function directly to `map` 
			// because `map` passes an index as the second argument, which
			// might be interpreted as recipientId by `makePublicKey`
			return makePublicKey(publicKey);
		}) :
		[ makePublicKey(publicKey, recipientId) ];

	if (recipients.length === 0) {
		throw new VirgilCryptoError('Cannot "singThenEncrypt". ' +
			'At least one recipient public key must be provided.');
	}

	var signer = new VirgilCrypto.VirgilSigner();
	var cipher = new VirgilCrypto.VirgilCipher();
	var signature;
	var customData;
	var dataByteArray = u.bufferToByteArray(data);

	try {
		signature = signer.sign(
			dataByteArray,
			signingKey.privateKey,
			signingKey.password
		);

		customData = cipher.customParams();
		customData.setData(u.stringToByteArray(constants.DATA_SIGNATURE_KEY), signature);
		if (signingKey.recipientId) {
			customData.setData(
				u.stringToByteArray(constants.DATA_SIGNER_ID_KEY),
				signingKey.recipientId
			);
		}

		recipients.forEach(function (recipient) {
			cipher.addKeyRecipient(recipient.recipientId, recipient.publicKey);
		});

		return u.byteArrayToBuffer(cipher.encrypt(dataByteArray, true));

	} catch (e) {
		throw new VirgilCryptoError(e.message);
	}
};
