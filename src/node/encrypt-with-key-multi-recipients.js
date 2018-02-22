var VirgilCrypto = require('../../virgil_js.node');
var u = require('./utils');
var VirgilCryptoError = require('./virgil-crypto-error');

module.exports = function encryptWithKeyMultiRecipients (initialData, recipients) {
	if (recipients.length === 0) {
		throw new VirgilCryptoError(
			'Cannot encrypt data, "recipients" array is empty.'
		);
	}

	var virgilCipher = new VirgilCrypto.VirgilCipher();

	recipients.forEach(function(recipient) {
		virgilCipher.addKeyRecipient(
			u.bufferToByteArray(recipient.recipientId),
			u.bufferToByteArray(recipient.publicKey));
	});

	var encryptedDataByteArray = virgilCipher.encrypt(u.bufferToByteArray(initialData), true);

	return u.byteArrayToBuffer(encryptedDataByteArray);
};
