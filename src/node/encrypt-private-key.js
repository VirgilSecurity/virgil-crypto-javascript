var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Encrypts private key with password
 *
 * @param {Buffer} privateKey - Private key to encrypt
 * @param {Buffer} privateKeyPassword - Password to encrypt with
 *
 * @returns {Buffer} Encrypted private key
 * 
 * */
module.exports = function encryptPrivateKey(privateKey, privateKeyPassword) {
	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	var encryptedKeyBytes = VirgilCrypto.VirgilKeyPair.encryptPrivateKey(
		u.bufferToByteArray(privateKey),
		u.bufferToByteArray(privateKeyPassword));

	return u.byteArrayToBuffer(encryptedKeyBytes);
};
