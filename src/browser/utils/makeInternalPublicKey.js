import { bufferToByteArray, byteArrayToBuffer, isBuffer, isObjectLike } from './crypto-utils';
import { throwVirgilError } from './crypto-errors';

/**
 * Converts the publicKey argument to canonical public key representation.
 *
 * @param {(Buffer|PublicKey)} publicKey
 * @param {Buffer} [recipientId]
 * @returns {InternalPublicKey}
 */
export function makeInternalPublicKey(publicKey, recipientId) {
	if (isBuffer(publicKey)) {
		if (!!recipientId && !isBuffer(recipientId)) {
			throwVirgilError('10000', {
				error: 'Unexpected type of "recipientId" argument. ' +
				'Expected recipientId to be a Buffer.'
			});
		}

		return new InternalPublicKey(publicKey, recipientId);
	}

	if (isObjectLike(publicKey) && !!publicKey.publicKey) {
		return new InternalPublicKey(publicKey.publicKey, publicKey.recipientId);
	}

	throwVirgilError('10000', {
		error: 'Unexpected type of "publicKey" argument. ' +
		'Expected publicKey to be a Buffer or a hash with "publicKey" property.'
	});
}

/**
 * Creates a new InternalPublicKey.
 *
 * @class
 * @classdesc Represents a public key consumable by native VirgilCrypto.
 */
function InternalPublicKey(key, recipientId) {
	this.publicKey = bufferToByteArray(key);
	this.recipientId = recipientId ? bufferToByteArray(recipientId) : null;
}

/**
 * Frees the memory held by the key's private members. The instance can no
 * longer be used after this method is called.
 */
InternalPublicKey.prototype.delete = function deletePublicKey() {
	this.publicKey.delete();
	this.recipientId && this.recipientId.delete();
};

/**
 * Returns a representation of this public key that is safe for transfer
 * to Web Worker context.
 *
 * @returns {{publicKey: string, [recipientId]: string}}
 */
InternalPublicKey.prototype.marshall = function marshall() {
	var res = {
		publicKey: byteArrayToBuffer(this.publicKey).toString('base64'),
		recipientId: this.recipientId ?
			byteArrayToBuffer(this.recipientId).toString('base64') :
			null
	};

	this.delete();
	return res;
};
