import expect from 'expect';
import { generateKeyPair } from '../generate-key-pair';
import { signThenEncrypt } from '../sign-then-encrypt';
import { decryptThenVerify } from '../decrypt-then-verify';
import VirgilCryptoError from '../../lib/Error';

describe('signThenEncrypt -> decryptThenVerify with multiple keys', function () {

	it('should decrypt and verify data successfully given right keys', function () {
		var plainData = new Buffer('Secret message');

		var senderKeyPair = generateKeyPair();
		var senderId = new Buffer('SENDER');

		var recipientKeyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT');

		var additionalKeyPair = generateKeyPair();
		var additionalId = new Buffer('Additional');

		var anotherKeyPair = generateKeyPair();
		var anotherId = new Buffer('Another');

		var encryptedData = signThenEncrypt(
			plainData,
			{
				privateKey: senderKeyPair.privateKey,
				recipientId: senderId
			},
			recipientId,
			recipientKeyPair.publicKey
		);

		var decryptedData = decryptThenVerify(
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
	});

	it('should fail verification given the wrong public key', function () {
		var plainData = new Buffer('Secret message');

		var senderKeyPair = generateKeyPair();
		var senderId = new Buffer('SENDER');

		var recipientKeyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT');

		var additionalKeyPair = generateKeyPair();
		var additionalId = new Buffer('Additional');

		var anotherKeyPair = generateKeyPair();
		var anotherId = new Buffer('Another');


		var encryptedData = signThenEncrypt(
			plainData,
			{
				privateKey: senderKeyPair.privateKey,
				recipientId: senderId
			},
			recipientId,
			recipientKeyPair.publicKey
		);

		expect(function() {
			decryptThenVerify(
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
		}).toThrow(VirgilCryptoError, /Signature verification has failed/);
	});

	it('should decrypt and verify without signer id in metadata', function () {
		var plainData = new Buffer('Secret message');

		var senderKeyPair = generateKeyPair();
		var senderId = new Buffer('SENDER');

		var recipientKeyPair = generateKeyPair();
		var recipientId = new Buffer('RECIPIENT');

		var additionalKeyPair = generateKeyPair();
		var additionalId = new Buffer('Additional');

		var anotherKeyPair = generateKeyPair();
		var anotherId = new Buffer('Another');

		var encryptedData = signThenEncrypt(
			plainData,
			senderKeyPair.privateKey, // no signer id is passed
			recipientId,
			recipientKeyPair.publicKey
		);

		var decryptedData = decryptThenVerify(
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
	});
});
