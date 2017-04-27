var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');
var VirgilCryptoError = require('./virgil-crypto-error');
var constants = require('../lib/constants');

/**
 * An object representing a private key used for calculating the signature.
 * @typedef {{privateKey: Buffer, id: Buffer, password: Buffer}} PrivateKey
 */

/**
 * An object representing a public key with an identifier.
 * @typedef {{recipientId:Buffer, publicKey:Buffer}} RecipientPublicKey
 */

/**
 * Signs and encrypts the data.
 *
 * @param {Buffer} data
 * @param {Buffer|PrivateKey} privateKey - The `privateKey` can be an
 * 		object or a Buffer. If `privateKey` is a Buffer, it is treated as a
 * 		raw key without password. If it is an object, it is interpreted as a
 * 		hash containing three properties: `privateKey`, optional `id` and optional
 * 		`password`.
 * @param {Buffer|RecipientPublicKey} recipientId -
 * 		Recipient ID if encrypting for single recipient OR
 * 		Array of recipientId - publicKey pairs if encrypting for multiple recipients
 * @param {Buffer} [publicKey] - Public key if encrypting for single recipient.
 * 		Ignored if encrypting for multiple recipients
 *
 * @returns {Buffer} Signed and encrypted data
 */
module.exports = function signThenEncrypt (data, privateKey, recipientId, publicKey) {
	u.checkIsBuffer(data, 'data');
	validatePrivateKey(privateKey);
	validatePublicKey(recipientId, publicKey);

	var recipients;
	var signingKey, signingKeyPassword, signingKeyId;

	if (u.isBuffer(privateKey)) {
		signingKey = u.bufferToByteArray(privateKey);
		signingKeyPassword = u.bufferToByteArray(new Buffer(''));
	} else {
		signingKey = u.bufferToByteArray(privateKey.privateKey);
		signingKeyPassword = u.bufferToByteArray(privateKey.password || new Buffer(''));
		signingKeyId = privateKey.id;
	}

	if (Array.isArray(recipientId)) {
		recipients = recipientId;
	} else {
		recipients = [{
			recipientId: recipientId,
			publicKey: publicKey
		}];
	}

	var signer = new VirgilCrypto.VirgilSigner();
	var cipher = new VirgilCrypto.VirgilCipher();
	var signature;
	var customData;
	var dataByteArray = u.bufferToByteArray(data);

	try {
		signature = signer.sign(
			dataByteArray,
			signingKey,
			signingKeyPassword
		);

		customData = cipher.customParams();
		customData.setData(u.stringToByteArray(constants.DATA_SIGNATURE_KEY), signature);
		if (signingKeyId) {
			customData.setData(
				u.stringToByteArray(constants.DATA_SIGNER_ID_KEY),
				u.bufferToByteArray(signingKeyId)
			);
		}

		recipients.forEach(function (recipient) {
			cipher.addKeyRecipient(
				u.bufferToByteArray(recipient.recipientId),
				u.bufferToByteArray(recipient.publicKey)
			);
		});

		return u.byteArrayToBuffer(cipher.encrypt(dataByteArray, true));

	} catch (e) {
		throw new VirgilCryptoError(e.message);
	}
};

function validatePrivateKey(key) {
	if (u.isBuffer(key)) {
		return;
	}

	if (u.isBuffer(key.privateKey) &&
		(!key.password || u.isBuffer(key.password)) &&
		(!key.id || u.isBuffer(key.id))) {
		return;
	}

	throw new VirgilCryptoError('Unexpected type of "privateKey" argument. ' +
		'Expected privateKey to be a Buffer or an hash with "privateKey" property.');
}

function validatePublicKey(recipientId, publicKey) {
	if (Array.isArray(recipientId)) {
		var recipients = recipientId;
		recipients.forEach(function (r) {
			u.checkIsBuffer(r.recipientId, 'recipient.recipientId');
			u.checkIsBuffer(r.publicKey, 'recipient.publicKey');
		})
	} else {
		u.checkIsBuffer(recipientId, 'recipientId');
		u.checkIsBuffer(publicKey, 'publicKey');
	}
}
