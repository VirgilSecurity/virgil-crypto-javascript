"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

var KEYS_TYPES_ENUM = VirgilCrypto.KeysTypesEnum;
var PASSWORD = new Buffer('veryStrongPa$$0rd');

describe('generaKeyPair', function () {
	var keyPair = {};

	describe('with default params', function () {
		beforeEach(function () {
			keyPair = VirgilCrypto.generateKeyPair();
		});

		it('"publicKey" should be defined', function () {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', function () {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" is not encrypted', function () {
			expect(keyPair.privateKey.toString('utf8')).toNotContain('ENCRYPTED');
		});
	});

	describe('with password', function () {
		beforeEach(function () {
			keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		});

		it('"publicKey" should be defined', function () {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', function () {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', function () {
			expect(keyPair.privateKey.toString('utf8')).toContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default"', function () {
		beforeEach(function () {
			keyPair = VirgilCrypto.generateKeyPair({ type: KEYS_TYPES_ENUM.Default });
		});

		it('"publicKey" should be defined', function () {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', function () {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', function () {
			expect(keyPair.privateKey.toString('utf8')).toNotContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default" and password', function () {
		beforeEach(function () {
			keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD, type: KEYS_TYPES_ENUM.Default });
		});

		it('"publicKey" should be defined', function () {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', function () {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', function () {
			expect(keyPair.privateKey.toString('utf8')).toContain('ENCRYPTED');
		});
	});

	describe('with specific type', function () {
		describe(KEYS_TYPES_ENUM.EC_SECP384R1, function () {
			beforeEach(function () {
				keyPair = VirgilCrypto.generateKeyPair({ type: KEYS_TYPES_ENUM.EC_SECP384R1 });
			});

			it('`publicKey` should be defined', function () {
				expect(keyPair.publicKey).toExist();
			});

			it('`privateKey` should be defined', function () {
				expect(keyPair.privateKey).toExist();
			});

			it('`privateKey` not encrypted', function () {
				expect(keyPair.privateKey.toString('utf8')).toNotContain('ENCRYPTED');
			});
		});
	});

	describe('with specific type and password', function () {
		describe(KEYS_TYPES_ENUM.EC_SECP384R1, function () {
			beforeEach(function () {
				keyPair = VirgilCrypto.generateKeyPair({ type: KEYS_TYPES_ENUM.EC_SECP384R1, password: PASSWORD });
			});

			it('`publicKey` should be defined', function () {
				expect(keyPair.publicKey).toExist();
			});

			it('`privateKey` should be defined', function () {
				expect(keyPair.privateKey).toExist();
			});

			it('`privateKey` not encrypted', function () {
				expect(keyPair.privateKey.toString('utf8')).toContain('ENCRYPTED');
			});
		});
	});

	describe('Change private key password', function () {
		var firstPassword = new Buffer('qwerty1');
		var secondPassword = new Buffer('qwerty2');
		var data = new Buffer('abc');
		var recipientId = new Buffer('im id');
		var keyPair = VirgilCrypto.generateKeyPair({ password: firstPassword });
		var updatedPrivateKey = VirgilCrypto.changePrivateKeyPassword(keyPair.privateKey, firstPassword, secondPassword);
		var encryptedData = VirgilCrypto.encrypt(data, recipientId, keyPair.publicKey, secondPassword);
		var decryptedData = VirgilCrypto.decrypt(encryptedData, recipientId, updatedPrivateKey, secondPassword);
		expect(decryptedData.equals(data)).toBe(true);
	});
});
