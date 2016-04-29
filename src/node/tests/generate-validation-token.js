"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

const PASSWORD = 'veryStrongPa$$0rd';
const IDENTITY_VALUE = 'email@example.com';

describe('sign/verify', () => {
	it('signed data should be verified', () => {
		let keyPair = VirgilCrypto.generateKeyPair(PASSWORD);
		let identityToken = VirgilCrypto.generateIdentityToken(
			IDENTITY_VALUE,
			VirgilCrypto.IdentityTypesEnum.custom,
			keyPair.privateKey,
			PASSWORD
		);
		console.log(identityToken);
	});

});
