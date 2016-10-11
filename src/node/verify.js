var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Verify signed data using public key
 *
 * @param {Buffer} data
 * @param {Buffer} sign
 * @param {Buffer} publicKey
 *
 * @returns {boolean}
 */
module.exports = function verify (data, sign, publicKey) {
	u.checkIsBuffer(data, 'data');
	u.checkIsBuffer(sign, 'sign');
	u.checkIsBuffer(publicKey, 'publicKey');

	var virgilSigner = new VirgilCrypto.VirgilSigner();

	return virgilSigner.verify(
		u.bufferToByteArray(data),
		u.bufferToByteArray(sign),
		u.bufferToByteArray(publicKey));
};
