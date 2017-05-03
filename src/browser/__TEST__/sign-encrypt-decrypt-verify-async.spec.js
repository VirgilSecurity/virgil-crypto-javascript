import expect from 'expect';
import { generateKeyPair } from '../generate-key-pair';
import { signThenEncrypt } from '../sign-then-encrypt';
import { signThenEncryptAsync } from '../sign-then-encrypt-async';
import { decryptThenVerify } from '../decrypt-then-verify';
import { decryptThenVerifyAsync } from '../decrypt-then-verify-async';

describe('signThenEncryptAsync -> decryptThenVerifyAsync', () => {

	it('should decrypt and verify data successfully given right keys', async (done) => {
		var keyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');
		var encryptedData = await signThenEncryptAsync(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var decryptedData = await decryptThenVerifyAsync(
			encryptedData,
			recipientId,
			keyPair.privateKey,
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
		done();

	});

	it('should fail verification given the wrong public key', async (done) => {
		var keyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');
		var encryptedData = await signThenEncryptAsync(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var wrongPubkey = generateKeyPair().publicKey;

		try {
			await decryptThenVerifyAsync(
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
		var keyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');
		var encryptedData = signThenEncrypt(
			plainData,
			keyPair.privateKey,
			recipientId,
			keyPair.publicKey);

		var decryptedData = await decryptThenVerifyAsync(
			encryptedData,
			recipientId,
			keyPair.privateKey,
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
		done();
	});

	it('should synchronously decrypt and verify data signed and encrypted asynchronously', async (done) => {
		var keyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');

		var encryptedData = await signThenEncryptAsync(
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
		done();
	});

	it('should sign with password-protected key', async function (done) {
		var password = new Buffer('pa$$w0rd');
		var keyPair = generateKeyPair({ password: password });
		var recipientId = new Buffer('RECIPIENT_ID');
		var plainData = new Buffer('Secret message');
		var encryptedData = await signThenEncryptAsync(
			plainData,
			{
				privateKey: keyPair.privateKey,
				password: password
			},
			recipientId,
			keyPair.publicKey);

		var decryptedData = await decryptThenVerifyAsync(
			encryptedData,
			recipientId,
			{
				privateKey: keyPair.privateKey,
				password: password
			},
			keyPair.publicKey);

		expect(decryptedData.equals(plainData)).toEqual(true);
		done();
	});
});
