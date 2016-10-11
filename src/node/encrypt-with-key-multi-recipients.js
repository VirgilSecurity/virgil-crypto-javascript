var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');

module.exports = function encryptWithKeyMultiRecipients (initialData, recipients) {
	var virgilCipher = new VirgilCrypto.VirgilCipher();

	recipients.forEach(function(recipient) {
		virgilCipher.addKeyRecipient(
			u.bufferToByteArray(recipient.recipientId),
			u.bufferToByteArray(recipient.publicKey));
	});

	var encryptedDataByteArray = virgilCipher.encrypt(u.bufferToByteArray(initialData), true);

	return u.byteArrayToBuffer(encryptedDataByteArray);
};
