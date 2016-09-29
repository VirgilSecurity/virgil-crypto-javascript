var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');


module.exports = function publicKeyToDER(publicKey) {
	var publicKeyByteArray = u.toByteArray(publicKey);
	var derByteArray = VirgilCrypto.VirgilKeyPair.publicKeyToDER(publicKeyByteArray);
	return u.byteArrayToBuffer(derByteArray);
};
