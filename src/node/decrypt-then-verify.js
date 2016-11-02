var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');
var VirgilCryptoError = require('./virgil-crypto-error');
var constants = require('../lib/constants');

/**
 * Decrypts the given data with private key and verify the signature with public key
 *
 * @param {Buffer} cipherData - Data to decrypt
 * @param {Buffer} recipientId - Recipient ID used for encryption
 * @param {Buffer} privateKey - Private key
 * @param {Buffer} publicKey - Public key to validate the signature with
 *
 * @returns {Buffer} Decrypted data
 * */
module.exports = function decryptThenVerify (cipherData, recipientId, privateKey, publicKey) {
	u.checkIsBuffer(cipherData, 'cipherData');
	u.checkIsBuffer(recipientId, 'recipientId');
	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(publicKey, 'publicKey');

	var signer = new VirgilCrypto.VirgilSigner();
	var cipher = new VirgilCrypto.VirgilCipher();
	var plainData;
	var signature;
	var isValid;

	try {
		plainData = cipher.decryptWithKey(
			u.bufferToByteArray(cipherData),
			u.bufferToByteArray(recipientId),
			u.bufferToByteArray(privateKey));

		signature = cipher.customParams().getData(u.stringToByteArray(constants.DATA_SIGNATURE_KEY));
		isValid = signer.verify(plainData, signature, u.bufferToByteArray(publicKey));
	} catch (e) {
		throw new VirgilCryptoError(e.message);
	}

	if (!isValid) {
		throw new VirgilCryptoError('Signature verification has failed.');
	}

	return u.byteArrayToBuffer(plainData);
};
