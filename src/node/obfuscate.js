var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

/**
 * Obfuscates data
 *
 * @param {Buffer} value - Value to be obfuscated
 * @param {Buffer} salt - The salt
 * @param {string} [algorithm] - Hash algorithm. Default is SHA384
 * @param {number} [iterations] - Number of iterations. Default is 2048.
 *
 * @returns {Buffer} - Obfuscated value
 * */
module.exports = function obfuscate (value, salt, algorithm, iterations) {
	iterations = iterations || 2048;
	algorithm = algorithm || VirgilCrypto.VirgilHash.Algorithm_SHA384;

	u.checkIsBuffer(value, 'value');
	u.checkIsBuffer(salt, 'salt');

	var pbkdf = new VirgilCrypto.VirgilPBKDF(u.bufferToByteArray(salt), iterations);
	pbkdf.setHashAlgorithm(algorithm);
	return u.byteArrayToBuffer(pbkdf.derive(u.bufferToByteArray(value)));
};
