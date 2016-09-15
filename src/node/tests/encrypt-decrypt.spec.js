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

	it('using keys "Default" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.Default);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "Default" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.Default, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_BP256R1" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP256R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_BP256R1" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP256R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_BP384R1" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP384R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_BP384R1" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP384R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_BP512R1" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP512R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_BP512R1" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP512R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP256K1" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256K1);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP256K1" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256K1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP256R1" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP256R1" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP384R1" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP384R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP384R1" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP384R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP521R1" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP521R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_SECP521R1" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP521R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_CURVE25519" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_CURVE25519);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_CURVE25519" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_CURVE25519, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_ED25519" without password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_ED25519);
		expect(decryptedData).toEqual(INITIAL_DATA);
	});

	it('using keys "EC_ED25519" with password', function () {
		var decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_ED25519, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
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
