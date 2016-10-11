var decryptWithKey = require('./decrypt-with-key');
var decryptWithPassword = require('./decrypt-with-password');
var u = require('./utils');

/**
 * Decrypts the given data with either private key or password
 *
 * @param {Buffer} encryptedData - Data to decrypt
 * @param {Buffer} recipientId|password - Recipient ID if decrypting with private key, otherwise password
 * @param {Buffer} [privateKey] - Private key
 * @param {Buffer} [privateKeyPassword] - Private key password (if private key is encrypted)
 *
 * @returns {Buffer} Decrypted data
 * */
module.exports = function decrypt (encryptedData, recipientId, privateKey, privateKeyPassword) {
	u.checkIsBuffer(encryptedData, 'encryptedData');
	u.checkIsBuffer(recipientId, 'recipientId');
	privateKey && u.checkIsBuffer(privateKey, 'privateKey');
	privateKeyPassword && u.checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	var decryptedData;

	if (arguments.length === 2) {
		var password = recipientId;

		decryptedData = decryptWithPassword(encryptedData, password);
	} else {
		decryptedData = decryptWithKey(encryptedData, recipientId, privateKey, privateKeyPassword);
	}

	return decryptedData;
};
