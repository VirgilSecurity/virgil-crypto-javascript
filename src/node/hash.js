var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Produces a hash of given data
 *
 * @param {Buffer} data - Data to hash
 * @param {string} [algorithm] - Hash algorithm to use. Default is SHA256
 *
 * @returns {Buffer}
 * */
module.exports = function hash(data, algorithm) {
	u.checkIsBuffer(data, 'data');

	algorithm = algorithm || VirgilCrypto.VirgilHash.Algorithm_SHA256;
	var virgilHash = new VirgilCrypto.VirgilHash(algorithm);
	var hash = virgilHash.hash(u.bufferToByteArray(data));
	return u.byteArrayToBuffer(hash);
};
