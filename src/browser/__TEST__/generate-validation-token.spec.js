import { VirgilCrypto, Buffer } from '../../../browser';

const identity = 'alice@example.com';
const identityType = 'email';
const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');
const tokenRegexp = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\.(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

describe('generate validation token', () => {
	it('it should generate validation token with plain key', () => {
		const keyPair = VirgilCrypto.generateKeyPair();
		const token = VirgilCrypto.generateValidationToken(identity, identityType, keyPair.privateKey);
		expect(token).toBeDefined();
		expect(Buffer.from(token, 'base64').toString('utf8')).toMatch(tokenRegexp);
	});

	it('it should generate validation token with encrypted key', () => {
		const keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		const token = VirgilCrypto.generateValidationToken(identity, identityType, keyPair.privateKey, PASSWORD);
		expect(token).toBeDefined();
		expect(Buffer.from(token, 'base64').toString('utf8')).toMatch(tokenRegexp);
	});
});
