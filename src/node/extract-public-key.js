var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function extractPublicKey(privateKey, privateKeyPassword) {
	var privateKeyByteArray = u.toByteArray(privateKey);
	var passwordByteArray = u.toByteArray(privateKeyPassword);

	var pubKeyByteArray = VirgilCrypto.VirgilKeyPair.extractPublicKey(privateKeyByteArray, passwordByteArray);
	return u.byteArrayToString(pubKeyByteArray);
};
