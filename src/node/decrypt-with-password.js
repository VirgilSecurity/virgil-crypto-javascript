var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function decryptWithPassword (encryptedData, password) {
	password = password || new Buffer(0);

	var virgilCipher = new VirgilCrypto.VirgilCipher();

	var decryptedDataByteArray = virgilCipher.decryptWithPassword(
		u.bufferToByteArray(encryptedData),
		u.bufferToByteArray(password));

	return u.byteArrayToBuffer(decryptedDataByteArray);
};
