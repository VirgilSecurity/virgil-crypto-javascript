var VirgilCrypto = require('../');
var expect = require('expect');

var PASSWORD = new Buffer('veryStrongPa$$0rd');

describe('Encrypt\\Decrypt private key', function () {
	it('should decrypt encrypted private key', function () {
		var keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		var decryptedKey = VirgilCrypto.decryptPrivateKey(keyPair.privateKey, PASSWORD);
		expect(decryptedKey.toString('utf8')).toNotContain('ENCRYPTED');
	});

	it('should encrypt plain private key', function () {
		var keyPair = VirgilCrypto.generateKeyPair();
		var encryptedKey = VirgilCrypto.encryptPrivateKey(keyPair.privateKey, PASSWORD);
		expect(encryptedKey.toString('utf8')).toContain('ENCRYPTED');
	});
});
