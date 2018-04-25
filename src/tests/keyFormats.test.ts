import { cryptoApi } from '../node/api';

describe('keys PEM - DER conversion', function () {
	const plaintext = new Buffer('data to be encrypted');
	const identifier = new Buffer('keypair_identifier');

	it('should decrypt data with private key in DER format', function () {
		const keyPair = cryptoApi.generateKeyPair();
		const privateKeyDer = cryptoApi.privateKeyToDer(keyPair.privateKey);
		const encryptedData = cryptoApi.encrypt(plaintext, { identifier, key: keyPair.publicKey });
		const decryptedData = cryptoApi.decrypt(encryptedData, { identifier, key: privateKeyDer });
		assert.isTrue(decryptedData.equals(plaintext));
	});

	it('should encrypt data with public key in DER format', function () {
		const keyPair = cryptoApi.generateKeyPair();
		const publicKeyDer = cryptoApi.publicKeyToDer(keyPair.publicKey);
		const encryptedData = cryptoApi.encrypt(plaintext, { identifier, key: publicKeyDer });
		const decryptedData = cryptoApi.decrypt(encryptedData, { identifier, key: keyPair.privateKey });
		assert.isTrue(decryptedData.equals(plaintext));
	});

	it('public key DER to DER conversion is noop', function () {
		const keyPair = cryptoApi.generateKeyPair();
		const firstPublicKeyDer = cryptoApi.publicKeyToDer(keyPair.publicKey);
		const secondPublicKeyDer = cryptoApi.publicKeyToDer(firstPublicKeyDer);
		assert.isTrue(secondPublicKeyDer.equals(firstPublicKeyDer));
	});

	it('private key DER to DER conversion is noop', function () {
		const keyPair = cryptoApi.generateKeyPair();
		const firstPrivateKeyDer = cryptoApi.privateKeyToDer(keyPair.privateKey);
		const secondPrivateKeyDer = cryptoApi.privateKeyToDer(firstPrivateKeyDer);
		assert.isTrue(secondPrivateKeyDer.equals(firstPrivateKeyDer));
	});

	it('extract returns public key in same format', function () {
		const keyPairPem = cryptoApi.generateKeyPair();
		const privateKeyDer = cryptoApi.privateKeyToDer(keyPairPem.privateKey);
		const publicKeyPem = cryptoApi.extractPublicKey(keyPairPem.privateKey);
		const publicKeyDer = cryptoApi.extractPublicKey(privateKeyDer);

		assert.isFalse(keyPairPem.privateKey.equals(privateKeyDer));
		assert.include(publicKeyPem.toString('utf8'), 'BEGIN');
		assert.isFalse(publicKeyPem.equals(publicKeyDer));
	});
});

