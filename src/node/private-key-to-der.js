var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function privateKeyToDER(privateKey, keyPassword) {
	var privateKeyByteArray = u.toByteArray(privateKey);
	var keyPasswordByteArray = u.toByteArray(keyPassword || '');

	var derByteArray = VirgilCrypto.VirgilKeyPair.privateKeyToDER(privateKeyByteArray, keyPasswordByteArray);
	return u.byteArrayToBuffer(derByteArray);
};
