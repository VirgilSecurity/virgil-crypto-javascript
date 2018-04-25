import { cryptoApi } from '../node/api';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');

describe('encrypt\\decrypt private key', () => {
	it('should decrypt encrypted private key', () => {
		const keyPair = cryptoApi.generateKeyPair({ password: PASSWORD });
		const decryptedKey = cryptoApi.decryptPrivateKey(keyPair.privateKey, PASSWORD);
		assert.notInclude(decryptedKey.toString('utf8'), 'ENCRYPTED');
	});

	it('should encrypt plain private key', () => {
		const keyPair = cryptoApi.generateKeyPair();
		const encryptedKey = cryptoApi.encryptPrivateKey(keyPair.privateKey, PASSWORD);
		assert.include(encryptedKey.toString('utf8'), 'ENCRYPTED');
	});
});
