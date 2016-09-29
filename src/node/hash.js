var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function hash(data, algorithm) {
	algorithm = algorithm || VirgilCrypto.VirgilHash.Algorithm_SHA256;
	var virgilHash = new VirgilCrypto.VirgilHash(algorithm);
	var hash = virgilHash.hash(u.toByteArray(data));
	return u.byteArrayToBuffer(hash);
};
