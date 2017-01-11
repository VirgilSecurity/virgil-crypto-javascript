import { VirgilCrypto, Buffer } from '../../../browser';

const KEY_PAIR_TYPE = VirgilCrypto.KeyPairType;
const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');

describe('generaKeyPair', () => {
	let keyPair = {};

	describe('with default params', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair();
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" is not encrypted', () => {
			expect(keyPair.privateKey.toString('utf8')).not.toContain('ENCRYPTED');
		});
	});

	describe('with password', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey.toString('utf8')).toContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default"', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair({ type: KEY_PAIR_TYPE.Default });
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey.toString('utf8')).not.toContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default" and password', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair({
				password: PASSWORD,
				type: KEY_PAIR_TYPE.Default
			});
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey.toString('utf8')).toContain('ENCRYPTED');
		});
	});

	describe('with specific type', () => {
		describe(`"${KEY_PAIR_TYPE.EC_SECP256R1}"`, () => {
			beforeAll(() => {
				keyPair = VirgilCrypto.generateKeyPair({ type: KEY_PAIR_TYPE.EC_SECP256R1 });
			});

			it('`publicKey` should be defined', () => {
				expect(keyPair.publicKey).toBeDefined();
			});

			it('`privateKey` should be defined', () => {
				expect(keyPair.privateKey).toBeDefined();
			});

			it('`privateKey` not encrypted', () => {
				expect(keyPair.privateKey.toString('utf8')).not.toContain('ENCRYPTED');
			});
		});
	});

	describe('change private key password', () => {
		it('Default', function () {
			var firstPassword = Buffer.from('qwerty1', 'utf8');
			var secondPassword = Buffer.from('qwerty2', 'utf8');
			var data = Buffer.from('abc', 'utf8');
			var recipientId = Buffer.from('im id', 'utf8');
			var keyPair = VirgilCrypto.generateKeyPair({ password: firstPassword });
			var updatedPrivateKey = VirgilCrypto.changePrivateKeyPassword(keyPair.privateKey, firstPassword, secondPassword);
			var encryptedData = VirgilCrypto.encrypt(data, recipientId, keyPair.publicKey, secondPassword);
			var decryptedData = VirgilCrypto.decrypt(encryptedData, recipientId, updatedPrivateKey, secondPassword);
			expect(decryptedData.equals(data)).toBe(true);
		});
	});
});
