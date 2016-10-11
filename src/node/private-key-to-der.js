var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Converts PEM formatted private key to DER format.
 * @param {Buffer} privateKey - Private key in PEM format
 * @param {Buffer} [privateKeyPassword] - Private key password, if encrypted.
 * @returns {Buffer}
 * */
module.exports = function privateKeyToDER(privateKey, privateKeyPassword) {
	privateKeyPassword = privateKeyPassword || new Buffer(0);

	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	var derByteArray = VirgilCrypto.VirgilKeyPair.privateKeyToDER(
		u.bufferToByteArray(privateKey),
		u.bufferToByteArray(privateKeyPassword));

	return u.byteArrayToBuffer(derByteArray);
};
