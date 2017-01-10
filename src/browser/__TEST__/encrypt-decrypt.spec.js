import { VirgilCrypto, Buffer } from '../../../browser';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');
const INITIAL_DATA = Buffer.from('initial data', 'utf8');

describe('encrypt/decrypt', () => {

	function encryptDecryptUsingKeyPair(initialData, keysType, password) {
		let keyPair = VirgilCrypto.generateKeyPair({
			password: password,
			type: keysType
		});
		let recipientId = VirgilCrypto.hash(keyPair.publicKey);
		let encryptedData = VirgilCrypto.encrypt(initialData, recipientId, keyPair.publicKey);
		let decryptedData = VirgilCrypto.decrypt(encryptedData, recipientId, keyPair.privateKey, password);

		return decryptedData;
	}

	it('using password', () => {
		let encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, PASSWORD);
		let decryptedData = VirgilCrypto.decrypt(encryptedData, PASSWORD);

		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using recommended type of keys without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using recommended type of keys with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, null, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "RSA_2048" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.RSA_2048);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "RSA_2048" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.RSA_2048, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_BP256R1" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_BP256R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_BP256R1" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_BP256R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_BP384R1" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_BP384R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_BP384R1" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_BP384R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_BP512R1" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_BP512R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_BP512R1" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_BP512R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP256K1" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP256K1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP256K1" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP256K1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP256R1" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP256R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP256R1" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP256R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP384R1" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP384R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP384R1" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP384R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP521R1" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP521R1);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "EC_SECP521R1" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.EC_SECP521R1, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "FAST_EC_CURVE25519" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.FAST_EC_X25519);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "FAST_EC_CURVE25519" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.FAST_EC_X25519, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "FAST_EC_ED25519" without password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.FAST_EC_ED25519);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('using keys "FAST_EC_ED25519" with password', () => {
		let decryptedData = encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeyPairTypes.FAST_EC_ED25519, PASSWORD);
		expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
	});

	it('should encrypt and decrypt data for multiple recipients', () => {
		const numRecipients = 5;
		const recipients = Array(numRecipients).fill(0).map(_ => {
			let keyPair = VirgilCrypto.generateKeyPair();
			return {
				recipientId: VirgilCrypto.hash(keyPair.publicKey),
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			};
		});

		let encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, recipients);

		recipients.forEach((r) => {
			let decryptedData = VirgilCrypto.decrypt(encryptedData, r.recipientId, r.privateKey);
			expect(decryptedData.equals(INITIAL_DATA)).toBe(true);
		});
	});

});
