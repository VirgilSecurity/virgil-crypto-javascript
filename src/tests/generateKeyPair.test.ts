import { cryptoApi } from '../node/api';
import { KeyPairType } from '../common';

const PASSWORD = new Buffer('veryStrongPa$$0rd');

describe('generateKeyPair', function () {

	it('with default params', function () {
		const keyPair = cryptoApi.generateKeyPair();
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it('with password', function () {
		const keyPair = cryptoApi.generateKeyPair({ password: PASSWORD });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'), 'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it('with specific type "Default"', function () {
		const keyPair = cryptoApi.generateKeyPair({ type: KeyPairType.Default });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it('with specific type "Default" and password', function () {
		const keyPair = cryptoApi.generateKeyPair({ password: PASSWORD, type: KeyPairType.Default });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it('with specific type EC_SECP384R1', function () {
		const keyPair = cryptoApi.generateKeyPair({ type: KeyPairType.EC_SECP384R1 });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it('with specific type EC_SECP384R1 and password', function () {
		const keyPair = cryptoApi.generateKeyPair({ type: KeyPairType.EC_SECP384R1, password: PASSWORD });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it('Change private key password', function () {
		const firstPassword = new Buffer('qwerty1');
		const secondPassword = new Buffer('qwerty2');
		const data = new Buffer('abc');
		const identifier = new Buffer('keypair_identifier');
		const keyPair = cryptoApi.generateKeyPair({ password: firstPassword });

		const updatedPrivateKey = cryptoApi.changePrivateKeyPassword(
			keyPair.privateKey,
			firstPassword,
			secondPassword
		);
		assert.isFalse(updatedPrivateKey.equals(keyPair.privateKey), 'private key is re-encrypted');

		const encryptedData = cryptoApi.encrypt(
			data,
			{ identifier, key: keyPair.publicKey }
		);
		const decryptedData = cryptoApi.decrypt(
			encryptedData,
			{ identifier, key: updatedPrivateKey, password: secondPassword }
		);
		assert.isTrue(decryptedData.equals(data));
	});
});
