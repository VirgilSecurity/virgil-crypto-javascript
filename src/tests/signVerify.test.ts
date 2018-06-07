import { cryptoWrapper } from '../node/wrapper';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');
const PLAINTEXT = Buffer.from('initial data', 'utf8');

describe('sign/verify', () => {

	it('should verify data signed with encrypted key', () => {
		const keyPair = cryptoWrapper.generateKeyPair({ password: PASSWORD });
		const signature = cryptoWrapper.sign(PLAINTEXT, { key: keyPair.privateKey, password: PASSWORD });
		const verified = cryptoWrapper.verify(PLAINTEXT, signature, { key: keyPair.publicKey });

		assert.isTrue(verified);
	});

	it('should verify data signed with plain key', () => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const signature = cryptoWrapper.sign(PLAINTEXT, { key: keyPair.privateKey });
		const verified = cryptoWrapper.verify(PLAINTEXT, signature, { key: keyPair.publicKey });

		assert.isTrue(verified);
	});

	it('should not verify data with wrong public key', () => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const signature = cryptoWrapper.sign(PLAINTEXT, { key: keyPair.privateKey });
		const wrongPublicKey = cryptoWrapper.generateKeyPair().publicKey;
		const verified = cryptoWrapper.verify(PLAINTEXT, signature, { key: wrongPublicKey });

		assert.isFalse(verified);
	});
});
