var encryptWithKeyMultiRecipients = require('./encrypt-with-key-multi-recipients');
var encryptWithKey = require('./encrypt-with-key');
var encryptWithPassword = require('./encrypt-with-password');
var u = require('./utils');

/**
 * Encrypts data with either single public key, list of public keys or password
 *
 * @param {Buffer} initialData - Data to encrypt
 * @param {Buffer|Array<{ recipientId: <Buffer>, publicKey: <Buffer> }>} recipientId|recipients|password -
 * Recipient ID if encrypting for single recipient OR Array of recipientId - publicKey pairs if encrypting
 * for multiple recipients OR password to encrypt with
 * @param {Buffer} [publicKey] - Public key
 *
 * @returns {Buffer} - Encrypted data
 */
module.exports = function encrypt (initialData, recipientId, publicKey) {
	var encryptedData, recipients;

	u.checkIsBuffer(initialData, 'initialData');
	if (Array.isArray(recipientId)) {
		recipients = recipientId;
	} else {
		u.checkIsBuffer(recipientId, 'recipientId|password');
	}

	if (recipients) {
		encryptedData = encryptWithKeyMultiRecipients(initialData, recipients);
	} else if (Buffer.isBuffer(recipientId) && Buffer.isBuffer(publicKey)) {
		encryptedData = encryptWithKey(initialData, recipientId, publicKey);
	} else {
		var password = recipientId;
		encryptedData = encryptWithPassword(initialData, password);
	}

	return encryptedData;
};
