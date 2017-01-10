var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function encryptWithPassword (initialData, password) {
	var embedContentInfo = true;

	password = password || new Buffer(0);

	var virgilCipher = new VirgilCrypto.VirgilCipher();

	virgilCipher.addPasswordRecipient(u.bufferToByteArray(password));

	var encryptedDataByteArray = virgilCipher.encrypt(u.bufferToByteArray(initialData), embedContentInfo);

	return u.byteArrayToBuffer(encryptedDataByteArray);
};
