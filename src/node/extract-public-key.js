var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Returns public key computed based on private key
 *
 * @param {Buffer} privateKey - Private key to extract from
 * @param {Buffer} [privateKeyPassword] - Private key password (if key is encrypted)
 *
 * @return {Buffer} Computed public key
 *
 * */
module.exports = function extractPublicKey(privateKey, privateKeyPassword) {
	privateKeyPassword = privateKeyPassword || new Buffer(0);
	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	var pubKeyByteArray = VirgilCrypto.VirgilKeyPair.extractPublicKey(
		u.bufferToByteArray(privateKey),
		u.bufferToByteArray(privateKeyPassword));

	return u.byteArrayToBuffer(pubKeyByteArray);
};
