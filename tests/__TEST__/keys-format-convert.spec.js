import { VirgilCrypto, Buffer } from '../../../browser';

describe('keys PEM - DER conversion', function () {
	var plaintext = Buffer.from('data to be encrypted', 'utf8');
	var recipientId = Buffer.from('recipient_id', 'utf8');
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
});
