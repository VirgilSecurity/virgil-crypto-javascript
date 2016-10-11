var VirgilCrypto = require('../');
var expect = require('expect');

var PASSWORD = new Buffer('veryStrongPa$$0rd');

describe('extract public key from private', function () {
	it ('should extract public key from encrypted private key', function () {
		var keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		var extractedPubKey = VirgilCrypto.extractPublicKey(keyPair.privateKey, PASSWORD);
		expect(extractedPubKey.equals(keyPair.publicKey)).toBe(true);
	});

	it ('should extract public key from non-encrypted private key', function () {
		var keyPair = VirgilCrypto.generateKeyPair();
		var extractedPubKey = VirgilCrypto.extractPublicKey(keyPair.privateKey);
		expect(extractedPubKey.equals(keyPair.publicKey)).toBe(true);
	});
});
