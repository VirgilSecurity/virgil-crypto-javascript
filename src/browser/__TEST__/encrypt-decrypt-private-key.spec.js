import { VirgilCrypto, Buffer } from '../../../browser';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');

describe('Encrypt\\Decrypt private key', () => {
	it('should decrypt encrypted private key', () => {
		const keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		const decryptedKey = VirgilCrypto.decryptPrivateKey(keyPair.privateKey, PASSWORD);
		expect(decryptedKey.toString('utf8')).not.toContain('ENCRYPTED');
	});

	it('should encrypt plain private key', () => {
		const keyPair = VirgilCrypto.generateKeyPair();
		const encryptedKey = VirgilCrypto.encryptPrivateKey(keyPair.privateKey, PASSWORD);
		expect(encryptedKey.toString('utf8')).toContain('ENCRYPTED');
	});
});
