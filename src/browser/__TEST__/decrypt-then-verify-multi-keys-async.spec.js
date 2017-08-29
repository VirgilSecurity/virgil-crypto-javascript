import expect from 'expect';
import { generateKeyPair } from '../generate-key-pair';
import { signThenEncryptAsync } from '../sign-then-encrypt-async';
import { decryptThenVerifyAsync } from '../decrypt-then-verify-async';

describe('signThenEncryptAsync -> decryptThenVerifyAsync with multiple keys', function () {

	it('should decrypt and verify data successfully given right keys', async function (done) {
		var plainData = new Buffer('Secret message');

		var senderKeyPair = generateKeyPair();
		var senderId = new Buffer('SENDER');

		var recipientKeyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT');

		var additionalKeyPair = generateKeyPair();
		var additionalId = new Buffer('Additional');

		var anotherKeyPair = generateKeyPair();
		var anotherId = new Buffer('Another');

		var encryptedData = await signThenEncryptAsync(
			plainData,
			{
				privateKey: senderKeyPair.privateKey,
				recipientId: senderId
			},
			recipientId,
			recipientKeyPair.publicKey
		);

		var decryptedData = await decryptThenVerifyAsync(
			encryptedData,
			recipientId,
			recipientKeyPair.privateKey,
			[
				{
					publicKey: additionalKeyPair.publicKey,
					recipientId: additionalId
				}, {
					publicKey: anotherKeyPair.publicKey,
					recipientId: anotherId
				}, {
					publicKey: senderKeyPair.publicKey,
					recipientId: senderId
				}
			]
		);

		expect(decryptedData.equals(plainData)).toEqual(true);
		done();
	});

	it('should fail verification given the wrong public key', async function (done) {
		var plainData = new Buffer('Secret message');

		var senderKeyPair = generateKeyPair();
		var senderId = new Buffer('SENDER');

		var recipientKeyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT');

		var additionalKeyPair = generateKeyPair();
		var additionalId = new Buffer('Additional');

		var anotherKeyPair = generateKeyPair();
		var anotherId = new Buffer('Another');


		var encryptedData = await signThenEncryptAsync(
			plainData,
			{
				privateKey: senderKeyPair.privateKey,
				recipientId: senderId
			},
			recipientId,
			recipientKeyPair.publicKey
		);

		try {
			await decryptThenVerifyAsync(
				encryptedData,
				recipientId,
				recipientKeyPair.privateKey,
				[
					{
						publicKey: additionalKeyPair.publicKey,
						recipientId: additionalId
					}, {
						publicKey: anotherKeyPair.publicKey,
						recipientId: anotherId
					}
				]
			);
		} catch (e) {
			if (/Signature verification has failed/.test(e.message)) {
				done();
			}
		}
	});

	it('should decrypt and verify without signer id in metadata', async function (done) {
		var plainData = new Buffer('Secret message');

		var senderKeyPair = generateKeyPair();
		var senderId = new Buffer('SENDER');

		var recipientKeyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT');

		var additionalKeyPair = generateKeyPair();
		var additionalId = new Buffer('Additional');

		var anotherKeyPair = generateKeyPair();
		var anotherId = new Buffer('Another');

		var encryptedData = await signThenEncryptAsync(
			plainData,
			senderKeyPair.privateKey, // no signer id is passed
			recipientId,
			recipientKeyPair.publicKey
		);

		var decryptedData = await decryptThenVerifyAsync(
			encryptedData,
			recipientId,
			recipientKeyPair.privateKey,
			[
				{
					publicKey: additionalKeyPair.publicKey,
					recipientId: additionalId
				}, {
					publicKey: anotherKeyPair.publicKey,
					recipientId: anotherId
				}, {
					publicKey: senderKeyPair.publicKey,
					recipientId: senderId
				}
			]
		);

		expect(decryptedData.equals(plainData)).toEqual(true);
		done();
	});
});
