"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

var KEYS_TYPES_ENUM = VirgilCrypto.KeysTypesEnum;
var PASSWORD = 'veryStrongPa$$0rd';

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
			expect(keyPair.privateKey).toNotContain('ENCRYPTED');
		});
	});

	describe('with password', function () {
		beforeEach(function () {
			keyPair = VirgilCrypto.generateKeyPair(PASSWORD);
		});

		it('"publicKey" should be defined', function () {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', function () {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', function () {
			expect(keyPair.privateKey).toContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default"', function () {
		beforeEach(function () {
			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.Default);
		});

		it('"publicKey" should be defined', function () {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', function () {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', function () {
			expect(keyPair.privateKey).toNotContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default" and password', function () {
		beforeEach(function () {
			keyPair = VirgilCrypto.generateKeyPair(PASSWORD, KEYS_TYPES_ENUM.Default);
		});

		it('"publicKey" should be defined', function () {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', function () {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', function () {
			expect(keyPair.privateKey).toContain('ENCRYPTED');
		});
	});

	describe('with specific type', function () {
		describe(KEYS_TYPES_ENUM.Default, function () {
			beforeEach(function () {
				keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.Default);
			});

			it('`publicKey` should be defined', function () {
				expect(keyPair.publicKey).toExist();
			});

			it('`privateKey` should be defined', function () {
				expect(keyPair.privateKey).toExist();
			});

			it('`privateKey` not encrypted', function () {
				expect(keyPair.privateKey).toNotContain('ENCRYPTED');
			});
		});
	});
});
