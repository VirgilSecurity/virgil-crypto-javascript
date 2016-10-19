"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

var PASSWORD = new Buffer('veryStrongPa$$0rd');
var IDENTITY_VALUE = 'email@example.com';
var IDENTITY_TYPE = 'email';

describe('generateValidationToken', function () {
	it('should generate validation token with plain key', function () {
		var keyPair = VirgilCrypto.generateKeyPair();
		var validationToken = VirgilCrypto.generateValidationToken(
			IDENTITY_VALUE,
			IDENTITY_TYPE,
			keyPair.privateKey
		);

		expect(typeof validationToken).toEqual('string');

		validateToken(validationToken, keyPair.publicKey);
	});

	it('should generate validation token with encrypted key', function () {
		var keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		var validationToken = VirgilCrypto.generateValidationToken(
			IDENTITY_VALUE,
			IDENTITY_TYPE,
			keyPair.privateKey,
			PASSWORD
		);

		expect(typeof validationToken).toEqual('string');

		validateToken(validationToken, keyPair.publicKey);
	});
});

function validateToken(validationToken, publicKey) {
	var decodedToken = new Buffer(validationToken, 'base64').toString('utf8');
	var parts = decodedToken.split('.');
	var uid = parts[0];
	var sign = parts[1];
	var signedData = new Buffer(uid + IDENTITY_TYPE + IDENTITY_VALUE);

	expect(VirgilCrypto.verify(signedData, new Buffer(sign, 'base64'), publicKey)).toEqual(true);
}
