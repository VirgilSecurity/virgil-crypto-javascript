"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

const PASSWORD = 'veryStrongPa$$0rd';
const IDENTITY_VALUE = 'email@example.com';

describe('generateValidationToken', () => {
	it('Validation token is generated', () => {
		let keyPair = VirgilCrypto.generateKeyPair(PASSWORD);
		let validationToken = VirgilCrypto.generateValidationToken(
			IDENTITY_VALUE,
			VirgilCrypto.IdentityTypesEnum.custom,
			keyPair.privateKey,
			PASSWORD
		);

		expect(typeof validationToken).toEqual('string');

		var decodedToken = new Buffer(validationToken, 'base64').toString('utf8');
		var splited = decodedToken.split('.');
		var uid = splited[0];
		var sign = splited[1];
		var signedData = uid + VirgilCrypto.IdentityTypesEnum.custom + IDENTITY_VALUE;

		expect(VirgilCrypto.verify(signedData, keyPair.publicKey, new Buffer(sign, 'base64'))).toEqual(true);
	});

});
