var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');
var makePrivateKey = require('./helpers/makePrivateKey');
var makePublicKey = require('./helpers/makePublicKey');
var VirgilCryptoError = require('./virgil-crypto-error');
var constants = require('../lib/constants');

/**
 * Decrypts the given data with private key and verify the signature with
 * public key.
 *
 * @param {Buffer} cipherData - Data to decrypt
 * @param {Buffer} recipientId - Recipient ID used for encryption
 * @param {Buffer|PrivateKeyInfo} privateKey - The `privateKey` can be an
 * 		object or a Buffer. If `privateKey` is a Buffer, it is treated as a
 * 		raw key without password. If it is an object, it is interpreted as a
 * 		hash containing two properties: `privateKey`, and `password`.
 * @param {Buffer|PublicKeyInfo[]} publicKey - Raw public key or an array of public
 * 		keys with identifiers to verify the signature with. If the cipher data
 * 		contains an identifier of the private key used to calculate the signature,
 * 		then the public key with that identifier from `publicKey` array will be
 * 		used to validate the signature, otherwise ANY one of the keys can validate
 * 		the signature. If the signature is not valid for ALL of the keys,
 * 		an exception is thrown.
 *
 * @returns {Buffer} Decrypted data
 * */
module.exports = function decryptThenVerify (cipherData, recipientId, privateKey, publicKey) {
	u.checkIsBuffer(cipherData, 'cipherData');
	u.checkIsBuffer(recipientId, 'recipientId');

	var decryptingKey = makePrivateKey(privateKey, null, recipientId);

	var publicKeys = Array.isArray(publicKey) ?
		publicKey.map(function (publicKey) {
			// don't pass `makePublicKey` function directly to `map`
			// because `map` passes an index as the second argument, which
			// might be interpreted as recipientId by `makePublicKey`
			return makePublicKey(publicKey);
		}) :
		[ makePublicKey(publicKey) ];

	if (publicKeys.length === 0) {
		throw new VirgilCryptoError('Unexpected argument "publicKey". ' +
			'At least one public key must be provided.');
	}

	var plainData;
	var signature;
	var signerId;
	var isValid;
	var cipher = new VirgilCrypto.VirgilCipher();

	try {
		plainData = cipher.decryptWithKey(
			u.bufferToByteArray(cipherData),
			u.bufferToByteArray(recipientId),
			decryptingKey.privateKey,
			decryptingKey.password
		);

		signature = cipher.customParams()
			.getData(u.stringToByteArray(constants.DATA_SIGNATURE_KEY));

		if (publicKeys.length === 1) {
			isValid = verifyWithKey(plainData, signature, publicKeys[0]);
		} else {
			signerId = tryGetSignerId(cipher);
			isValid = verifyWithMultipleKeys(plainData, signature, publicKeys, signerId);
		}

	} catch (e) {
		throw new VirgilCryptoError(e.message);
	}

	if (!isValid) {
		throw new VirgilCryptoError('Signature verification has failed.');
	}

	return u.byteArrayToBuffer(plainData);
};

function verifyWithKey(data, signature, publicKey) {
	var signer = new VirgilCrypto.VirgilSigner();
	return signer.verify(data, signature, publicKey.publicKey);
}

function verifyWithMultipleKeys(data, signature, publicKeys, signerId) {
	var signer = new VirgilCrypto.VirgilSigner();

	if (signerId) {
		// find the public key corresponding to signer id from metadata
		var signerPublicKey = publicKeys.find(function (publicKey) {
			return u.byteArraysEqual(signerId, publicKey.recipientId);
		});

		if (!signerPublicKey) {
			return false;
		}

		return signer.verify(data, signature, signerPublicKey.publicKey);
	}

	// no signer id in metadata, try all public keys in sequence
	return publicKeys.some(function (publicKey) {
		return signer.verify(data, signature, publicKey.publicKey);
	});
}

function tryGetSignerId(cipher) {
	var customParams = cipher.customParams();
	var key = u.stringToByteArray(constants.DATA_SIGNER_ID_KEY);
	try {
		return customParams.getData(key);
	} catch (e) {
		return null;
	}
}
