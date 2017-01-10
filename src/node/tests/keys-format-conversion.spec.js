var VirgilCrypto = require('../');
var expect = require('expect');

describe('keys PEM - DER conversion', function () {
	var plaintext = new Buffer('data to be encrypted');
	var recipientId = new Buffer('recipient_id');
	var keyPair;

	beforeEach(function () {
		keyPair = VirgilCrypto.generateKeyPair();
	});

	it('should decrypt data with private key in DER format', function () {
		var privateKeyDER = VirgilCrypto.privateKeyToDER(keyPair.privateKey);
		var encryptedData = VirgilCrypto.encrypt(plaintext, recipientId, keyPair.publicKey);
		var decryptedData = VirgilCrypto.decrypt(encryptedData, recipientId, privateKeyDER);
		expect(decryptedData.equals(plaintext)).toBe(true);
	});

	it('should encrypt data with public key in DER format', function () {
		var publicKeyDER = VirgilCrypto.publicKeyToDER(keyPair.publicKey);
		var encryptedData = VirgilCrypto.encrypt(plaintext, recipientId, publicKeyDER);
		var decryptedData = VirgilCrypto.decrypt(encryptedData, recipientId, keyPair.privateKey);
		expect(decryptedData.equals(plaintext)).toBe(true);
	});

	it('public key DER to DER conversion is noop', function () {
		var firstPublicKeyDER = VirgilCrypto.publicKeyToDER(keyPair.publicKey);
		var secondPublicKeyDER = VirgilCrypto.publicKeyToDER(firstPublicKeyDER);
		expect(secondPublicKeyDER.equals(firstPublicKeyDER)).toBe(true);
	});

	it('private key DER to DER conversion is noop', function () {
		var firstPrivateKeyDER = VirgilCrypto.privateKeyToDER(keyPair.privateKey);
		var secondPrivateKeyDER = VirgilCrypto.privateKeyToDER(firstPrivateKeyDER);
		expect(secondPrivateKeyDER.equals(firstPrivateKeyDER)).toBe(true);
	});

	it('extract returns pubkey in same format', function () {
		var pubkey = VirgilCrypto.extractPublicKey(keyPair.privateKey);
		var pubkeyDER = VirgilCrypto.publicKeyToDER(pubkey);

		expect(pubkey.toString('utf8').indexOf('BEGIN') > 0).toBe(true);
		expect(pubkey.equals(pubkeyDER)).toBe(false);
	});
});

