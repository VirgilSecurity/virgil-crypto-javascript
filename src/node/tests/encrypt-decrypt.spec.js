"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

var PASSWORD = new Buffer('veryStrongPa$$0rd', 'utf8');
var INITIAL_DATA = new Buffer('initial data', 'utf8');

describe('encrypt/decrypt', function () {
	this.timeout(5000);

	function encryptDecryptUsingKeyPair(initialData, keysType, password) {
		var keyPair = VirgilCrypto.generateKeyPair({ password: password, type: keysType });
		var encryptedData = VirgilCrypto.encrypt(initialData, keyPair.publicKey, keyPair.publicKey);
		var decryptedData = VirgilCrypto.decrypt(encryptedData, keyPair.publicKey, keyPair.privateKey, password);

		return decryptedData;
	}

	it('using password', function () {
		var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, PASSWORD);
		var decryptedData = VirgilCrypto.decrypt(encryptedData, PASSWORD);

		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	Object.keys(VirgilCrypto.KeyPairType)
	.filter(function (keyType) {
		return keyType !== 'RSA_8192' && keyType !== 'RSA_4096';
	})
	.forEach(function (keyType) {
		it('using keys \''+keyType+'\' without password', function () {
			var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType[keyType]);
			expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		});

		it('using keys \''+keyType+'\' with password', function () {
			var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType[keyType], PASSWORD);
			expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		});
	});

	it('Tiny Cipher', function () {
		var data = 'this is sample data';
		var keyPair = VirgilCrypto.generateKeyPair();
		var tiny = new VirgilCrypto.VirgilTinyCipher(128);
		tiny.encrypt(data, keyPair.publicKey);
		var encryptedPackage = tiny.getPackage(0);

		var decryptTiny = new VirgilCrypto.VirgilTinyCipher(128);
		decryptTiny.addPackage(encryptedPackage);
		expect(decryptTiny.isPackagesAccumulated()).toEqual(true);
		expect(decryptTiny.decrypt(keyPair.privateKey).toString('utf8')).toEqual(data);
	});

	it('should encrypt and decrypt data for multiple recipients', function () {
		var numRecipients = 3;
		var recipients = [];
		var keyPair;
		for (var i = 0; i < numRecipients; i++) {
			keyPair = VirgilCrypto.generateKeyPair();
			recipients.push({
				recipientId: VirgilCrypto.hash(keyPair.publicKey),
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			});
		}

		var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, recipients);

		recipients.forEach(function (r) {
			var decryptedData = VirgilCrypto.decrypt(encryptedData, r.recipientId, r.privateKey);
			expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		});
	});

	it('encrypt should throw when passed empty array of recipients', function () {
		var recipients = [];

		expect(function () {
			VirgilCrypto.encrypt(INITIAL_DATA, recipients);
		}).toThrow(VirgilCrypto.VirgilCryptoError);
	});
});
