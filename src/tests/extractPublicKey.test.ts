import { cryptoApi } from '../node/api';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');

describe('extract public key from private', () => {
	it ('should extract public key from encrypted private key', () => {
		const keyPair = cryptoApi.generateKeyPair({ password: PASSWORD });
		const extractedPubKey = cryptoApi.extractPublicKey(keyPair.privateKey, PASSWORD);
		assert.isTrue(extractedPubKey.equals(keyPair.publicKey));
	});

	it ('should extract public key from non-encrypted private key', () => {
		const keyPair = cryptoApi.generateKeyPair();
		const extractedPubKey = cryptoApi.extractPublicKey(keyPair.privateKey);
		assert.isTrue(extractedPubKey.equals(keyPair.publicKey));
	});
});
