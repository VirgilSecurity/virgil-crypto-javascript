var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Changes the password used to encrypt the private key
 *
 * @param {Buffer} privateKey - The private key
 * @param {Buffer} oldPassword - Old password
 * @param {Buffer} newPassword - New password
 *
 * @returns {Buffer} Encrypted private key
 * */
module.exports = function changePrivateKeyPassword (privateKey, oldPassword, newPassword) {
	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(oldPassword, 'oldPassword');
	u.checkIsBuffer(newPassword, 'newPassword');

	return u.byteArrayToBuffer(VirgilCrypto.VirgilKeyPair.resetPrivateKeyPassword(
		u.bufferToByteArray(privateKey),
		u.bufferToByteArray(oldPassword),
		u.bufferToByteArray(newPassword)
	));
};
