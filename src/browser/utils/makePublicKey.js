import { bufferToByteArray, byteArrayToBuffer, isBuffer, isObjectLike } from './crypto-utils';
import { throwVirgilError } from './crypto-errors';

/**
 * Converts the publicKey argument to canonical public key representation.
 *
 * @param {(Buffer|PublicKeyInfo)} publicKey
 * @param {Buffer} [recipientId]
 * @returns {PublicKey}
 */
export function makePublicKey(publicKey, recipientId) {
	if (isBuffer(publicKey)) {
		if (!!recipientId && !isBuffer(recipientId)) {
			throwVirgilError('10000', {
				error: 'Unexpected type of "recipientId" argument. ' +
				'Expected recipientId to be a Buffer.'
			});
		}

		return new PublicKey(publicKey, recipientId);
	}

	if (isObjectLike(publicKey) && !!publicKey.publicKey) {
		return new PublicKey(publicKey.publicKey, publicKey.recipientId);
	}

	throwVirgilError('10000', {
		error: 'Unexpected type of "publicKey" argument. ' +
		'Expected publicKey to be a Buffer or a hash with "publicKey" property.'
	});
}

/**
 * Creates a new PublicKey.
 *
 * @class
 * @classdesc A wrapper around the public key value and id.
 * 		Byte array properties of instances are represented as
 * 		VirgilByteArray - type consumable by native VirgilCrypto.
 */
function PublicKey(key, recipientId) {
	this.publicKey = bufferToByteArray(key);
	this.recipientId = recipientId ? bufferToByteArray(recipientId) : null;
}

/**
 * Frees the memory held by the key's private members. The instance can no
 * longer be used after this method is called.
 */
PublicKey.prototype.delete = function deletePublicKey() {
	this.publicKey.delete();
	this.recipientId && this.recipientId.delete();
};

/**
 * Returns a representation of this public key that is safe for transfer
 * to Web Worker context.
 *
 * @returns {{publicKey: string, [recipientId]: string}}
 */
PublicKey.prototype.marshall = function marshall() {
	var res = {
		publicKey: byteArrayToBuffer(this.publicKey).toString('base64'),
		recipientId: this.recipientId ?
			byteArrayToBuffer(this.recipientId).toString('base64') :
			null
	};

	this.delete();
	return res;
};
