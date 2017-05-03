import expect from 'expect';
import { generateKeyPair } from '../generate-key-pair';
import { signThenEncrypt } from '../sign-then-encrypt';
import { decryptThenVerify } from '../decrypt-then-verify';

describe('signThenEncrypt -> decryptThenVerify', function () {

	it('should decrypt and verify data successfully given right keys', function () {
		var keyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');
		var encryptedData = signThenEncrypt(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var decryptedData = decryptThenVerify(
			encryptedData,
			recipientId,
			keyPair.privateKey,
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
	});

	it('should fail verification given the wrong public key', function () {
		var keyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');
		var encryptedData = signThenEncrypt(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var wrongPubkey = generateKeyPair().publicKey;

		expect(function() {
			decryptThenVerify(
				encryptedData,
				recipientId,
				keyPair.privateKey,
				wrongPubkey);
		}).toThrow(/Signature verification has failed/);
	});

	it('should sign with password-protected key', function () {
		var password = new Buffer('pa$$w0rd');
		var keyPair = generateKeyPair({ password: password });
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');
		var encryptedData = signThenEncrypt(
			plainData,
			{
				privateKey: keyPair.privateKey,
				password: password
			},
			recipientId,
			keyPair.publicKey);

		var decryptedData = decryptThenVerify(
			encryptedData,
			recipientId,
			{
				privateKey: keyPair.privateKey,
				password: password
			},
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
	});
});
