'use strict';

var utils = require('../utils');
var VirgilCryptoError = require('../virgil-crypto-error');

module.exports = makePrivateKey;

/**
 * Converts the privateKey argument to canonical private key representation.
 *
 * @param {(Buffer|PrivateKeyInfo)} privateKey
 * @param {Buffer} [password]
 * @param {Buffer} [recipientId]
 *
 * @private
 *
 * @returns {PrivateKey}
 */
function makePrivateKey(privateKey, password, recipientId) {
	if (!utils.isBuffer(privateKey)) {
		if (utils.isObjectLike(privateKey) && utils.isBuffer(privateKey.privateKey)) {
			var key = privateKey;
			privateKey = key.privateKey;
			password = key.password || password;
			recipientId = key.recipientId || recipientId;
		} else {
			throw new VirgilCryptoError('Unexpected type of "privateKey" argument. ' +
				'Expected privateKey to be a Buffer or a hash with "privateKey" property.');
		}
	}

	if (!!password && !utils.isBuffer(password)) {
		throw new VirgilCryptoError('Unexpected type of "password" argument. ' +
			'Expected password to be a Buffer. Got ' + recipientId);
	}

	if (!!recipientId && !utils.isBuffer(recipientId)) {
		throw new VirgilCryptoError('Unexpected type of "recipientId" argument. ' +
			'Expected recipientId to be a Buffer. Got ' + recipientId);
	}

	return new PrivateKey(privateKey, password, recipientId);
}

/**
 * Creates a new InternalPrivateKey.
 *
 * @private
 * @class
 * @classdesc A wrapper around the private key value password and id.
 * 		Byte array properties of instances are represented as
 * 		VirgilByteArray - type consumable by native VirgilCrypto.
 */
function PrivateKey(key, password, recipientId) {
	/** @type {VirgilByteArray} */
	this.privateKey = utils.bufferToByteArray(key);
	/** @type {VirgilByteArray} */
	this.password = utils.bufferToByteArray(password || new Buffer(''));
	/** @type {VirgilByteArray} */
	this.recipientId = recipientId ? utils.bufferToByteArray(recipientId) : null;
}
