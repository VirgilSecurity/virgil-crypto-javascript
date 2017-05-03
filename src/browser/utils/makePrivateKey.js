import { bufferToByteArray, byteArrayToBuffer, isBuffer, isObjectLike } from './crypto-utils';
import { throwVirgilError } from './crypto-errors';

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
export function makePrivateKey(privateKey, password, recipientId) {
	if (isBuffer(privateKey)) {
		if (!!password && !isBuffer(password)) {
			throwVirgilError('10000', {
				error: 'Unexpected type of "password" argument. ' +
				'Expected password to be a Buffer.'
			});
		}

		if (!!recipientId && !isBuffer(recipientId)) {
			throwVirgilError('10000', {
				error: 'Unexpected type of "recipientId" argument. ' +
				'Expected recipientId to be a Buffer.'
			});
		}

		return new PrivateKey(privateKey, password, recipientId);
	}

	if (isObjectLike(privateKey) && !!privateKey.privateKey) {
		if (!!privateKey.password && !isBuffer(privateKey.password)) {
			throwVirgilError('10000', {
				error: 'Unexpected type of "privateKey" argument. ' +
				'Expected "password" property to be a Buffer.'
			});
		}

		if (!!privateKey.recipientId && !isBuffer(privateKey.recipientId)) {
			throwVirgilError('10000', {
				error: 'Unexpected type of "privateKey" argument. ' +
				'Expected "recipientId" property to be a Buffer.'
			});
		}

		return new PrivateKey(
			privateKey.privateKey,
			privateKey.password,
			privateKey.recipientId
		);
	}

	throwVirgilError('10000', {
		error: 'Unexpected type of "privateKey" argument. ' +
		'Expected privateKey to be a Buffer or a hash with "privateKey" property.'
	});
}

/**
 * Creates a new PrivateKey.
 *
 * @private
 * @class
 * @classdesc A wrapper around the private key value password and id.
 * 		Byte array properties of instances are represented as
 * 		VirgilByteArray - type consumable by native VirgilCrypto.
 */
function PrivateKey(key, password, recipientId) {
	/** @type {VirgilByteArray} */
	this.privateKey = bufferToByteArray(key);
	/** @type {VirgilByteArray} */
	this.password = bufferToByteArray(password || new Buffer(''));
	/** @type {VirgilByteArray} */
	this.recipientId = recipientId ? bufferToByteArray(recipientId) : null;
}

/**
 * Frees the memory held by the key's private members. The instance can no
 * longer be used after this method is called.
 */
PrivateKey.prototype.delete = function deletePrivateKey() {
	this.privateKey.delete();
	this.password.delete();
	this.recipientId && this.recipientId.delete();
};

/**
 * Returns a representation of this private key that is safe for transfer
 * to Web Worker context.
 *
 * @returns {{privateKey: string, password: string, [recipientId]: string}}
 */
PrivateKey.prototype.marshall = function marshall() {
	var res = {
		privateKey: byteArrayToBuffer(this.privateKey).toString('base64'),
		password: byteArrayToBuffer(this.password).toString('base64'),
		recipientId: this.recipientId ?
			byteArrayToBuffer(this.recipientId).toString('base64') :
			null
	};

	this.delete();
	return res;
};
