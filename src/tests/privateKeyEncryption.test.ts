import { cryptoWrapper } from '../virgilCryptoWrapper';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');

describe('encrypt\\decrypt private key', () => {
	it('should decrypt encrypted private key', () => {
		const keyPair = cryptoWrapper.generateKeyPair({ password: PASSWORD });
		const decryptedKey = cryptoWrapper.decryptPrivateKey(keyPair.privateKey, PASSWORD);
		assert.notInclude(decryptedKey.toString('utf8'), 'ENCRYPTED');
	});

	it('should encrypt plain private key', () => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const encryptedKey = cryptoWrapper.encryptPrivateKey(keyPair.privateKey, PASSWORD);
		assert.include(encryptedKey.toString('utf8'), 'ENCRYPTED');
	});
});
