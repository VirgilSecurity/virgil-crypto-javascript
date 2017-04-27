var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');
var VirgilCryptoError = require('./virgil-crypto-error');
var constants = require('../lib/constants');

/**
 * Represents a public key with an identifier.
 * @typedef {{publicKey: Buffer, id: Buffer}} PublicKey
 */

/**
 * Decrypts the given data with private key and verify the signature with
 * public key.
 *
 * @param {Buffer} cipherData - Data to decrypt
 * @param {Buffer} recipientId - Recipient ID used for encryption
 * @param {Buffer|PrivateKey} privateKey - The `privateKey` can be an
 * 		object or a Buffer. If `privateKey` is a Buffer, it is treated as a
 * 		raw key without password. If it is an object, it is interpreted as a
 * 		hash containing three properties: `privateKey`, and `password`.
 * @param {Buffer|PublicKey[]} publicKey - Raw public key or an array of public
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
	validatePrivateKey(privateKey);
	validatePublicKey(publicKey);

	var decryptingKey, decryptingKeyPassword;
	if (u.isBuffer(privateKey)) {
		decryptingKey = u.bufferToByteArray(privateKey);
		decryptingKeyPassword = u.bufferToByteArray(new Buffer(''));
	} else {
		decryptingKey = u.bufferToByteArray(privateKey.privateKey);
		decryptingKeyPassword = u.bufferToByteArray(privateKey.password || new Buffer(''));
	}

	var publicKeys;
	if (u.isBuffer(publicKey)) {
		publicKeys = [{ publicKey: publicKey, id: null }];
	} else {
		publicKeys = publicKey;
	}

	if (publicKeys.length === 0) {
		throw new VirgilCryptoError('Unexpected argument "publicKey". ' +
			'At least one public key must be provided.');
	}

	publicKeys = publicKeys.map(function (publicKey) {
		return {
			publicKey: u.bufferToByteArray(publicKey.publicKey),
			id: publicKey.id ? u.bufferToByteArray(publicKey.id) : null
		};
	});

	var plainData;
	var signature;
	var signerId;
	var isValid;
	var cipher = new VirgilCrypto.VirgilCipher();

	try {
		plainData = cipher.decryptWithKey(
			u.bufferToByteArray(cipherData),
			u.bufferToByteArray(recipientId),
			decryptingKey,
			decryptingKeyPassword
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

function validatePublicKey(publicKey) {
	if (u.isBuffer(publicKey)) {
		return;
	}

	if (Array.isArray(publicKey)) {
		var publicKeys = publicKey;
		publicKeys.forEach(function (publicKey) {
			u.checkIsBuffer(publicKey.id, 'publicKey[].id');
			u.checkIsBuffer(publicKey.publicKey, 'publicKey[].publicKey');
		});

		return;
	}

	throw new VirgilCryptoError('Unexpected type of "publicKey" argument. ' +
		'Expected "publicKey" to be a Buffer or an array.');
}

function verifyWithKey(data, signature, publicKey) {
	var signer = new VirgilCrypto.VirgilSigner();
	return signer.verify(data, signature, publicKey.publicKey);
}

function verifyWithMultipleKeys(data, signature, publicKeys, signerId) {
	var signer = new VirgilCrypto.VirgilSigner();

	if (signerId) {
		// find the public key corresponding to signer id from metadata
		var signerPublicKey = publicKeys.find(function (publicKey) {
			return u.byteArraysEqual(signerId, publicKey.id);
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
