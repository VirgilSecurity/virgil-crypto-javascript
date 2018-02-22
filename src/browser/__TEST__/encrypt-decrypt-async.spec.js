import { VirgilCrypto, Buffer } from '../../../browser';
import VirgilCryptoError from '../../lib/Error';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');
const INITIAL_DATA = Buffer.from('initial data', 'utf8');

describe('encrypt/decrypt', () => {

	async function encryptDecryptUsingKeyPair(initialData, keysType, password) {
		let keyPair = VirgilCrypto.generateKeyPair({ password: password, type: keysType });
		let recipientId = VirgilCrypto.hash(keyPair.publicKey);
		let encryptedData = await VirgilCrypto.encryptAsync(initialData, recipientId, keyPair.publicKey);
		let decryptedData = await VirgilCrypto.decryptAsync(encryptedData, recipientId, keyPair.privateKey, password);

		return decryptedData;
	}

	it('using password', async (cb) => {
		let encryptedData = await VirgilCrypto.encryptAsync(INITIAL_DATA, PASSWORD);
		let decryptedData = await VirgilCrypto.decryptAsync(encryptedData, PASSWORD);

		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using recommended keys type without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using recommended keys type with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, null, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_BP256R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_BP256R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_BP256R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_BP256R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_BP384R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_BP384R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_BP384R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_BP384R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_BP512R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_BP512R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_BP512R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_BP512R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP256K1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP256K1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP256K1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP256K1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP256R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP256R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP256R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP256R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP384R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP384R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP384R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP384R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP521R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP521R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "EC_SECP521R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.EC_SECP521R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "FAST_EC_X25519" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.FAST_EC_X25519);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "FAST_EC_X25519" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.FAST_EC_X25519, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "FAST_EC_ED25519" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.FAST_EC_ED25519);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('using keys "FAST_EC_ED25519" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairType.FAST_EC_ED25519, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		cb();
	});

	it('should encrypt and decrypt data for multiple recipients', async (cb) => {
		const numRecipients = 5;
		const recipients = Array(numRecipients).fill(0).map(_ => {
			let keyPair = VirgilCrypto.generateKeyPair();
			return {
				recipientId: VirgilCrypto.hash(keyPair.publicKey),
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			};
		});

		let encryptedData = await VirgilCrypto.encryptAsync(INITIAL_DATA, recipients);

		recipients.forEach(async (r) => {
			let decryptedData = await VirgilCrypto.decryptAsync(encryptedData, r.recipientId, r.privateKey);
			expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		});

		cb();
	});

	it('encryptAsync should throw synchronous error when passed empty array of recipients', () => {
		const recipients = [];
		expect(() => {
			VirgilCrypto.encryptAsync(INITIAL_DATA, recipients);
		}).toThrowError(VirgilCryptoError);
	})
});
