import { VirgilCrypto, Buffer } from '../../../browser';

describe('signThenEncryptAsync -> decryptThenVerifyAsync', () => {
	var keyPair;
	var recipientId;

	beforeEach(function () {
		keyPair = VirgilCrypto.generateKeyPair();
		recipientId = VirgilCrypto.hash(keyPair.publicKey);
	});

	it('should decrypt and verify data successfully given right keys', async (done) => {
		var plainData = new Buffer('Secret message');
		var encryptedData = await VirgilCrypto.signThenEncryptAsync(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var decryptedData = await VirgilCrypto.decryptThenVerifyAsync(
			encryptedData,
			recipientId,
			keyPair.privateKey,
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
		done();

	});

	it('should fail verification given the wrong public key', async (done) => {
		var plainData = new Buffer('Secret message');
		var encryptedData = await VirgilCrypto.signThenEncryptAsync(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var wrongPubkey = VirgilCrypto.generateKeyPair().publicKey;
		
		try {
			await VirgilCrypto.decryptThenVerifyAsync(
				encryptedData,
				recipientId,
				keyPair.privateKey,
				wrongPubkey);
		} catch (err) {
			if (/Signature verification has failed/.test(err.message)) {
				done();
			}
		}
	});

	it('should asynchronously decrypt and verify data signed and encrypted synchronously', async (done) => {
		var plainData = new Buffer('Secret message');
		var encryptedData = VirgilCrypto.signThenEncrypt(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var decryptedData = await VirgilCrypto.decryptThenVerifyAsync(
			encryptedData,
			recipientId,
			keyPair.privateKey,
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
		done();
	});

	it('should synchronously decrypt and verify data signed and encrypted asynchronously', async (done) => {
		var plainData = new Buffer('Secret message');

		var encryptedData = await VirgilCrypto.signThenEncryptAsync(
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
		done();
	});
});
