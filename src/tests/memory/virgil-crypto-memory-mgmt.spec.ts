/**
 * @fileinfo
 * Test that ensures that asm.js memory is properly freed in browsers.
 * Number of iterations is chosen so that the tests do not run forever,
 * but still provide a good enough proof that memory does not leak.
 * This file has `.spec` prefix so that it doesn't run in node.js,
 * where the memory is managed automatically.
 */

import { VirgilCrypto } from '../../index';

describe('memory management in "sign" and "verify"', function() {
	this.timeout(180 * 1000);

	it('should not throw when called one thousand times', () => {
		const virgilCrypto = new VirgilCrypto();
		for (let i = 0; i < 1000; i += 1) {
			const keyPair = virgilCrypto.generateKeys();
			const message = 'message'.repeat(10);
			const signature = virgilCrypto.calculateSignature(message, keyPair.privateKey);
			const isValid = virgilCrypto.verifySignature(message, signature, keyPair.publicKey);
			assert.isTrue(isValid, 'verifies signature');
		}
	});
});

describe('memory management in "encrypt" and "decrypt"', function() {
	this.timeout(180 * 1000);

	it('should not throw when called 5 hundred times', () => {
		const virgilCrypto = new VirgilCrypto();
		for (let i = 0; i < 500; i += 1) {
			const keyPair = virgilCrypto.generateKeys();
			const message = 'message'.repeat(10);
			const ciphertext = virgilCrypto.encrypt(message, keyPair.publicKey);
			const decrypted = virgilCrypto.decrypt(ciphertext, keyPair.privateKey);
			assert.equal(decrypted.toString(), message, 'decrypts message');
		}
	});
});

describe('memory management in "signThenEncrypt" and "decryptThenVerify"', function() {
	this.timeout(180 * 1000);

	it('should not throw when called 5 hundred times', () => {
		const virgilCrypto = new VirgilCrypto();
		for (let i = 0; i < 500; i += 1) {
			const keyPair = virgilCrypto.generateKeys();
			const message = 'message'.repeat(10);
			const ciphertext = virgilCrypto.signThenEncrypt(message, keyPair.privateKey, keyPair.publicKey);
			const decrypted = virgilCrypto.decryptThenVerify(ciphertext, keyPair.privateKey, keyPair.publicKey);
			assert.equal(decrypted.toString(), message, 'decrypts and verifies message');
		}
	});
});

describe('memory management in "signThenEncryptDetached" and "decryptThenVerifyDetached"', function() {
	this.timeout(180 * 1000);

	it('should not throw when called 5 hundred times', () => {
		const virgilCrypto = new VirgilCrypto();
		for (let i = 0; i < 500; i += 1) {
			const keyPair = virgilCrypto.generateKeys();
			const message = 'message'.repeat(10);
			const { encryptedData, metadata } = virgilCrypto.signThenEncryptDetached(message, keyPair.privateKey, keyPair.publicKey);
			const decrypted = virgilCrypto.decryptThenVerifyDetached(encryptedData, metadata, keyPair.privateKey, keyPair.publicKey);
			assert.equal(decrypted.toString(), message, 'decrypts and verifies message');
		}
	});
});
