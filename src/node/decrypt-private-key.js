var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Decrypts the private key
 *
 * @param {Buffer} privateKey - Private key to decrypt
 * @param {Buffer} privateKeyPassword - Current private key password
 *
 * @returns {Buffer} Decrypted private key
 * */
module.exports = function decryptPrivateKey(privateKey, privateKeyPassword) {
	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	var decryptedKeyBytes = VirgilCrypto.VirgilKeyPair.decryptPrivateKey(
		u.bufferToByteArray(privateKey),
		u.bufferToByteArray(privateKeyPassword));

	return u.byteArrayToBuffer(decryptedKeyBytes);
};
