'use strict';

var expect = require('expect');
var generateKeyPair = require('../generate-key-pair');
var signThenEncrypt = require('../sign-then-encrypt');
var decryptThenVerify = require('../decrypt-then-verify');
var VirgilCryptoError = require('../virgil-crypto-error');

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
				id: senderId
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
					id: additionalId
				}, {
					publicKey: anotherKeyPair.publicKey,
					id: anotherId
				}, {
					publicKey: senderKeyPair.publicKey,
					id: senderId
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
				id: senderId
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
						id: additionalId
					}, {
						publicKey: anotherKeyPair.publicKey,
						id: anotherId
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
					id: additionalId
				}, {
					publicKey: anotherKeyPair.publicKey,
					id: anotherId
				}, {
					publicKey: senderKeyPair.publicKey,
					id: senderId
				}
			]
		);

		expect(decryptedData.equals(plainData)).toEqual(true);
	});
});
