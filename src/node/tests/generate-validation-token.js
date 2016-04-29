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
	});

});
