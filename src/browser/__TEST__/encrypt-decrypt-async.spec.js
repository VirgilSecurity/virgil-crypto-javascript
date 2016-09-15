import { VirgilCrypto } from '../../../browser';

const PASSWORD = 'veryStrongPa$$0rd';
const INITIAL_DATA = 'initial data';

describe('encrypt/decrypt', () => {

	async function encryptDecryptUsingKeyPair(initialData, keysType, password = '') {
		let keyPair = VirgilCrypto.generateKeyPair({ password: password, type: keysType });
		let encryptedData = await VirgilCrypto.encryptAsync(initialData, keyPair.publicKey, keyPair.publicKey);
		let decryptedData = await VirgilCrypto.decryptAsync(encryptedData, keyPair.publicKey, keyPair.privateKey, password);

		return decryptedData.toString('utf8');
	}

	it('using password', async (cb) => {
		let encryptedData = await VirgilCrypto.encryptAsync(INITIAL_DATA, PASSWORD);
		let decryptedData = await VirgilCrypto.decryptAsync(encryptedData, PASSWORD);

		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "Default" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.Default);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "Default" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.Default, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_BP256R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP256R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_BP256R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP256R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_BP384R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP384R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_BP384R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP384R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_BP512R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP512R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_BP512R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_BP512R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP256K1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256K1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP256K1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256K1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP256R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP256R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP256R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP384R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP384R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP384R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP384R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP521R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP521R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP521R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP521R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_CURVE25519" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_CURVE25519);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_CURVE25519" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_CURVE25519, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_ED25519" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_ED25519);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_ED25519" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_ED25519, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

});
