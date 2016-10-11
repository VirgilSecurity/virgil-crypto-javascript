var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Converts PEM formatted public key to DER format.
 * @param {Buffer} publicKey - Public key in PEM format
 * @returns {Buffer}
 * */
module.exports = function publicKeyToDER(publicKey) {
	u.checkIsBuffer(publicKey, 'publicKey');
	var derByteArray = VirgilCrypto.VirgilKeyPair.publicKeyToDER(u.bufferToByteArray(publicKey));
	return u.byteArrayToBuffer(derByteArray);
};
