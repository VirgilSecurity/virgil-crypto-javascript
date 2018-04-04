"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

var PASSWORD = new Buffer('veryStrongPa$$0rd');
var INITIAL_DATA = new Buffer('initial data');

describe('sign/verify', function () {

	it('should verify data signed with encrypted key', function () {
		var keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, keyPair.publicKey, keyPair.publicKey);
		var sign = VirgilCrypto.sign(encryptedData, keyPair.privateKey, PASSWORD);
		var verified = VirgilCrypto.verify(encryptedData, sign, keyPair.publicKey);

		expect(verified).toEqual(true);
	});

	it('should verify data signed with plain key', function () {
		var keyPair = VirgilCrypto.generateKeyPair();
		var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, keyPair.publicKey, keyPair.publicKey);
		var sign = VirgilCrypto.sign(encryptedData, keyPair.privateKey);
		var verified = VirgilCrypto.verify(encryptedData, sign, keyPair.publicKey);

		expect(verified).toEqual(true);
	});
});
