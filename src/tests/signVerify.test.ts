import { cryptoApi } from '../node/api';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');
const PLAINTEXT = Buffer.from('initial data', 'utf8');

describe('sign/verify', () => {

	it('should verify data signed with encrypted key', () => {
		const keyPair = cryptoApi.generateKeyPair({ password: PASSWORD });
		const signature = cryptoApi.sign(PLAINTEXT, { key: keyPair.privateKey, password: PASSWORD });
		const verified = cryptoApi.verify(PLAINTEXT, signature, { key: keyPair.publicKey });

		assert.isTrue(verified);
	});

	it('should verify data signed with plain key', () => {
		const keyPair = cryptoApi.generateKeyPair();
		const signature = cryptoApi.sign(PLAINTEXT, { key: keyPair.privateKey });
		const verified = cryptoApi.verify(PLAINTEXT, signature, { key: keyPair.publicKey });

		assert.isTrue(verified);
	});

	it('should not verify data with wrong public key', () => {
		const keyPair = cryptoApi.generateKeyPair();
		const signature = cryptoApi.sign(PLAINTEXT, { key: keyPair.privateKey });
		const wrongPublicKey = cryptoApi.generateKeyPair().publicKey;
		const verified = cryptoApi.verify(PLAINTEXT, signature, { key: wrongPublicKey });

		assert.isFalse(verified);
	});
});
