import { VirgilCrypto, Buffer } from '../../../browser';

const IDENTITY_VALUE = 'alice@example.com';
const IDENTITY_TYPE = 'email';
const PASSWORD = new Buffer('veryStrongPa$$0rd');

describe('generate validation token', () => {
	it('should generate validation token with plain key', () => {
		const keyPair = VirgilCrypto.generateKeyPair();
		const validationToken = VirgilCrypto.generateValidationToken(
			IDENTITY_VALUE,
			IDENTITY_TYPE,
			keyPair.privateKey
		);

		expect(typeof validationToken).toEqual('string');

		validateToken(validationToken, keyPair.publicKey);
	});

	it('should generate validation token with encrypted key', () => {
		const keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		const validationToken = VirgilCrypto.generateValidationToken(
			IDENTITY_VALUE,
			IDENTITY_TYPE,
			keyPair.privateKey,
			PASSWORD
		);

		expect(typeof validationToken).toEqual('string');

		validateToken(validationToken, keyPair.publicKey);
	});
});

function validateToken(validationToken, publicKey) {
	const decodedToken = new Buffer(validationToken, 'base64').toString('utf8');
	const parts = decodedToken.split('.');
	const uid = parts[0];
	const sign = parts[1];
	const signedData = new Buffer(uid + IDENTITY_TYPE + IDENTITY_VALUE);

	expect(VirgilCrypto.verify(signedData, new Buffer(sign, 'base64'), publicKey)).toEqual(true);
}
