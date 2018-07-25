import { cryptoWrapper } from '../virgilCryptoWrapper';

describe('keys PEM - DER conversion', function () {
	const plaintext = Buffer.from('data to be encrypted');
	const identifier = Buffer.from('keypair_identifier');

	it('should decrypt data with private key in DER format', function () {
		const keyPair = cryptoWrapper.generateKeyPair();
		const privateKeyDer = cryptoWrapper.privateKeyToDer(keyPair.privateKey);
		const encryptedData = cryptoWrapper.encrypt(plaintext, { identifier, key: keyPair.publicKey });
		const decryptedData = cryptoWrapper.decrypt(encryptedData, { identifier, key: privateKeyDer });
		assert.isTrue(decryptedData.equals(plaintext));
	});

	it('should encrypt data with public key in DER format', function () {
		const keyPair = cryptoWrapper.generateKeyPair();
		const publicKeyDer = cryptoWrapper.publicKeyToDer(keyPair.publicKey);
		const encryptedData = cryptoWrapper.encrypt(plaintext, { identifier, key: publicKeyDer });
		const decryptedData = cryptoWrapper.decrypt(encryptedData, { identifier, key: keyPair.privateKey });
		assert.isTrue(decryptedData.equals(plaintext));
	});

	it('public key DER to DER conversion is noop', function () {
		const keyPair = cryptoWrapper.generateKeyPair();
		const firstPublicKeyDer = cryptoWrapper.publicKeyToDer(keyPair.publicKey);
		const secondPublicKeyDer = cryptoWrapper.publicKeyToDer(firstPublicKeyDer);
		assert.isTrue(secondPublicKeyDer.equals(firstPublicKeyDer));
	});

	it('private key DER to DER conversion is noop', function () {
		const keyPair = cryptoWrapper.generateKeyPair();
		const firstPrivateKeyDer = cryptoWrapper.privateKeyToDer(keyPair.privateKey);
		const secondPrivateKeyDer = cryptoWrapper.privateKeyToDer(firstPrivateKeyDer);
		assert.isTrue(secondPrivateKeyDer.equals(firstPrivateKeyDer));
	});

	it('extract returns public key in same format', function () {
		const keyPairPem = cryptoWrapper.generateKeyPair();
		const privateKeyDer = cryptoWrapper.privateKeyToDer(keyPairPem.privateKey);
		const publicKeyPem = cryptoWrapper.extractPublicKey(keyPairPem.privateKey);
		const publicKeyDer = cryptoWrapper.extractPublicKey(privateKeyDer);

		assert.isFalse(keyPairPem.privateKey.equals(privateKeyDer));
		assert.include(publicKeyPem.toString('utf8'), 'BEGIN');
		assert.isFalse(publicKeyPem.equals(publicKeyDer));
	});
});

