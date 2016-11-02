import { VirgilCrypto, Buffer } from '../../../browser';

describe('signThenEncrypt -> decryptThenVerify', function () {

	var keyPair;
	var recipientId;

	beforeEach(function () {
		keyPair = VirgilCrypto.generateKeyPair();
		recipientId = VirgilCrypto.hash(keyPair.publicKey);
	});

	it('should decrypt and verify data successfully given right keys', function () {
		var plainData = new Buffer('Secret message');
		var encryptedData = VirgilCrypto.signThenEncrypt(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var decryptedData = VirgilCrypto.decryptThenVerify(
			encryptedData,
			recipientId,
			keyPair.privateKey,
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
	});

	it('should fail verification given the wrong public key', function () {
		var plainData = new Buffer('Secret message');
		var encryptedData = VirgilCrypto.signThenEncrypt(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var wrongPubkey = VirgilCrypto.generateKeyPair().publicKey;

		expect(function() {
			VirgilCrypto.decryptThenVerify(
				encryptedData,
				recipientId,
				keyPair.privateKey,
				wrongPubkey);
		}).toThrow();
	});
});
