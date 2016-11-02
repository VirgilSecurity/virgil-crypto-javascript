var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');
var VirgilCryptoError = require('./virgil-crypto-error');
var constants = require('../lib/constants');

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
module.exports = function signThenEncrypt (data, privateKey, recipientId, publicKey) {
	var recipients;

	if (Array.isArray(recipientId)) {
		recipients = recipientId;
	} else {
		recipients = [{
			recipientId: recipientId,
			publicKey: publicKey
		}];
	}

	u.checkIsBuffer(data, 'data');
	u.checkIsBuffer(privateKey, 'privateKey');
	recipients.forEach(function (recipient) {
		u.checkIsBuffer(recipient.recipientId, 'recipient.recipientId');
		u.checkIsBuffer(recipient.publicKey, 'recipient.publicKey');
	});

	var signer = new VirgilCrypto.VirgilSigner();
	var cipher = new VirgilCrypto.VirgilCipher();
	var signature;
	var customData;

	try {
		signature = signer.sign(u.bufferToByteArray(data), u.bufferToByteArray(privateKey));
		customData = cipher.customParams();
		customData.setData(u.stringToByteArray(constants.DATA_SIGNATURE_KEY), signature);

		recipients.forEach(function (recipient) {
			cipher.addKeyRecipient(u.bufferToByteArray(recipient.recipientId), u.bufferToByteArray(recipient.publicKey));
		});

		return u.byteArrayToBuffer(cipher.encrypt(u.bufferToByteArray(data), true));

	} catch (e) {
		throw new VirgilCryptoError(e.message);
	}
};

