var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function decryptWithKey (encryptedData, recipientId, privateKey, privateKeyPassword) {
	privateKeyPassword = privateKeyPassword || new Buffer(0);

	var virgilCipher = new VirgilCrypto.VirgilCipher();

	var decryptedDataByteArray = virgilCipher.decryptWithKey(
		u.bufferToByteArray(encryptedData),
		u.bufferToByteArray(recipientId),
		u.bufferToByteArray(privateKey),
		u.bufferToByteArray(privateKeyPassword));

	return u.byteArrayToBuffer(decryptedDataByteArray);
};
