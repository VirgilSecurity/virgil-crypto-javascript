import { cryptoWrapper } from '../node/wrapper';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');

describe('extract public key from private', () => {
	it ('should extract public key from encrypted private key', () => {
		const keyPair = cryptoWrapper.generateKeyPair({ password: PASSWORD });
		const extractedPubKey = cryptoWrapper.extractPublicKey(keyPair.privateKey, PASSWORD);
		assert.isTrue(extractedPubKey.equals(keyPair.publicKey));
	});

	it ('should extract public key from non-encrypted private key', () => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const extractedPubKey = cryptoWrapper.extractPublicKey(keyPair.privateKey);
		assert.isTrue(extractedPubKey.equals(keyPair.publicKey));
	});
});
