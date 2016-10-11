var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Sign the encrypted data using private key
 *
 * @param {Buffer} data
 * @param {Buffer} privateKey
 * @param {Buffer} [privateKeyPassword = '']
 *
 * @returns {Buffer} Signature
 */
module.exports = function sign (data, privateKey, privateKeyPassword) {
	privateKeyPassword = privateKeyPassword || new Buffer(0);

	u.checkIsBuffer(data, 'data');
	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	var virgilSigner = new VirgilCrypto.VirgilSigner();

	var sign = virgilSigner.sign(
		u.bufferToByteArray(data),
		u.bufferToByteArray(privateKey),
		u.bufferToByteArray(privateKeyPassword));

	return u.byteArrayToBuffer(sign);
};
