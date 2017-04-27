"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

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
		}).toThrow(VirgilCrypto.VirgilCryptoError, /Signature verification has failed/);
	});

	it('should sign with password-protected key', function () {
		var password = new Buffer('pa$$w0rd');
		var keyPair = VirgilCrypto.generateKeyPair({ password: password });
		var plainData = new Buffer('Secret message');
		var encryptedData = VirgilCrypto.signThenEncrypt(
			plainData,
			{
				privateKey: keyPair.privateKey,
				password: password
			},
			recipientId,
			keyPair.publicKey);

		var decryptedData = VirgilCrypto.decryptThenVerify(
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
