"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

const KEYS_TYPES_ENUM = VirgilCrypto.KeysTypesEnum;
const PASSWORD = 'veryStrongPa$$0rd';

describe('generaKeyPair', () => {
	let keyPair = {};

	describe('with default params', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair();
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" is not encrypted', () => {
			expect(keyPair.privateKey).toNotContain('ENCRYPTED');
		});
	});

	describe('with password', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair(PASSWORD);
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey).toContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default"', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.Default);
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey).toNotContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default" and password', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair(PASSWORD, KEYS_TYPES_ENUM.Default);
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toExist();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toExist();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey).toContain('ENCRYPTED');
		});
	});

	describe('with specific type', () => {
		describe(`"${KEYS_TYPES_ENUM.Default}"`, () => {
			beforeEach(() => {
				keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.Default);
			});

			it('`publicKey` should be defined', () => {
				expect(keyPair.publicKey).toExist();
			});

			it('`privateKey` should be defined', () => {
				expect(keyPair.privateKey).toExist();
			});

			it('`privateKey` not encrypted', () => {
				expect(keyPair.privateKey).toNotContain('ENCRYPTED');
			});
		});
	});
});
