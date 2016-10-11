var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function encryptWithPassword (initialData, password, isEmbeddedContentInfo) {
	password = password || new Buffer(0);
	isEmbeddedContentInfo = typeof isEmbeddedContentInfo === 'boolean' ? isEmbeddedContentInfo : true;

	var virgilCipher = new VirgilCrypto.VirgilCipher();

	virgilCipher.addPasswordRecipient(u.bufferToByteArray(password));

	var encryptedDataByteArray = virgilCipher.encrypt(u.bufferToByteArray(initialData), isEmbeddedContentInfo);

	return u.byteArrayToBuffer(encryptedDataByteArray);
};
