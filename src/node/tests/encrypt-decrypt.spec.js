"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

var PASSWORD = 'veryStrongPa$$0rd';
var INITIAL_DATA = 'initial data';

describe('encrypt/decrypt', function () {

	function encryptDecryptUsingKeyPair(initialData, keysType, password) {
		password = password || '';

		var keyPair = VirgilCrypto.generateKeyPair({ password: password, type: keysType });
		var encryptedData = VirgilCrypto.encrypt(initialData, keyPair.publicKey, keyPair.publicKey);
		var decryptedData = VirgilCrypto.decrypt(encryptedData, keyPair.publicKey, keyPair.privateKey, password);

		return decryptedData.toString('utf8');
	}

	it('using password', function () {
		var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, PASSWORD);
		var decryptedData = VirgilCrypto.decrypt(encryptedData, PASSWORD);

		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	Object.keys(VirgilCrypto.KeysTypesEnum)
	.filter(function (keyType) {
		return keyType !== 'RSA_8192' && keyType !== 'RSA_4096';
	})
	.forEach(function (keyType) {
		it('using keys \''+keyType+'\' without password', function () {
			var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum[keyType]);
			expect(decryptedData).toEqual(INITIAL_DATA);
		});

		it('using keys \''+keyType+'\' with password', function () {
			var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum[keyType], PASSWORD);
			expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
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
});
