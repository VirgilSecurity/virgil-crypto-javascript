import { cryptoWrapper } from '../node/wrapper';
import { KeyPairType } from '../common';

const PASSWORD = Buffer.from('veryStrongPa$$0rd');

describe('generateKeyPair', function () {

	it('with default params', function () {
		const keyPair = cryptoWrapper.generateKeyPair();
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it('with password', function () {
		const keyPair = cryptoWrapper.generateKeyPair({ password: PASSWORD });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'), 'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it('with specific type "Default"', function () {
		const keyPair = cryptoWrapper.generateKeyPair({ type: KeyPairType.Default });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it('with specific type "Default" and password', function () {
		const keyPair = cryptoWrapper.generateKeyPair({ password: PASSWORD, type: KeyPairType.Default });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it('with specific type EC_SECP384R1', function () {
		const keyPair = cryptoWrapper.generateKeyPair({ type: KeyPairType.EC_SECP384R1 });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it('with specific type EC_SECP384R1 and password', function () {
		const keyPair = cryptoWrapper.generateKeyPair({ type: KeyPairType.EC_SECP384R1, password: PASSWORD });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it('Change private key password', function () {
		const firstPassword = Buffer.from('qwerty1');
		const secondPassword = Buffer.from('qwerty2');
		const data = Buffer.from('abc');
		const identifier = Buffer.from('keypair_identifier');
		const keyPair = cryptoWrapper.generateKeyPair({ password: firstPassword });

		const updatedPrivateKey = cryptoWrapper.changePrivateKeyPassword(
			keyPair.privateKey,
			firstPassword,
			secondPassword
		);
		assert.isFalse(updatedPrivateKey.equals(keyPair.privateKey), 'private key is re-encrypted');

		const encryptedData = cryptoWrapper.encrypt(
			data,
			{ identifier, key: keyPair.publicKey }
		);
		const decryptedData = cryptoWrapper.decrypt(
			encryptedData,
			{ identifier, key: updatedPrivateKey, password: secondPassword }
		);
		assert.isTrue(decryptedData.equals(data));
	});
});
