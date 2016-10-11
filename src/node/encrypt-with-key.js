var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function encryptWithKey (initialData, recipientId, publicKey) {
	var virgilCipher = new VirgilCrypto.VirgilCipher();

	virgilCipher.addKeyRecipient(u.bufferToByteArray(recipientId), u.bufferToByteArray(publicKey));

	var encryptedDataByteArray = virgilCipher.encrypt(u.bufferToByteArray(initialData), true);

	return u.byteArrayToBuffer(encryptedDataByteArray);
};
