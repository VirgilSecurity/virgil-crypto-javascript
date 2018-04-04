import { VirgilCrypto, Buffer } from '../../../browser';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');

describe('extract public key from private', () => {
	it ('should extract public key from encrypted private key', () => {
		const keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		const extractedPubKey = VirgilCrypto.extractPublicKey(keyPair.privateKey, PASSWORD);
		expect(extractedPubKey.equals(keyPair.publicKey)).toBe(true);
	});

	it ('should extract public key from non-encrypted private key', () => {
		const keyPair = VirgilCrypto.generateKeyPair();
		const extractedPubKey = VirgilCrypto.extractPublicKey(keyPair.privateKey);
		expect(extractedPubKey.equals(keyPair.publicKey)).toBe(true);
	});
});
