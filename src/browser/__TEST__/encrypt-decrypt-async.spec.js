import { VirgilCrypto } from '../../../browser';

const PASSWORD = 'veryStrongPa$$0rd';
const INITIAL_DATA = 'initial data';

describe('encrypt/decrypt', () => {

	async function encryptDecryptUsingKeyPair(initialData, keysType, password = '') {
		let keyPair = VirgilCrypto.generateKeyPair(password, keysType);
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

	it('using keys "EC_M221" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M221);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_M221" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M221, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_M255" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M255);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_M255" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M255, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_M383" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M383);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_M383" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M383, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_M511" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M511);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_M511" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_M511, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP192K1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP192K1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP192K1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP192K1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP192R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP192R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP192R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP192R1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP224K1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP224K1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP224K1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP224K1, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP224R1" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP224R1);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "EC_SECP224R1" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.EC_SECP224R1, PASSWORD);
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

	it('using keys "RSA_256" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_256);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "RSA_256" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_256, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "RSA_512" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_512);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "RSA_512" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_512, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "RSA_1024" without password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_1024);
		expect(decryptedData).toEqual(INITIAL_DATA);
		cb();
	});

	it('using keys "RSA_1024" with password', async (cb) => {
		let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_1024, PASSWORD);
		expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
		cb();
	});

	//it('using keys "RSA_3072" without password', async (cb) => {
	//	let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_3072);
	//	expect(decryptedData).toEqual(INITIAL_DATA);
	//	cb();
	//});
  //
	//it('using keys "RSA_3072" with password', async (cb) => {
	//	let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_3072, PASSWORD);
	//	expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	//	cb();
	//});
  //
	//it('using keys "RSA_4096" without password', async (cb) => {
	//	let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_4096);
	//	expect(decryptedData).toEqual(INITIAL_DATA);
	//	cb();
	//});
  //
	//it('using keys "RSA_4096" with password', async (cb) => {
	//	let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_4096, PASSWORD);
	//	expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	//	cb();
	//});
  //
	//it('using keys "RSA_8192" without password', async (cb) => {
	//	let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_8192);
	//	expect(decryptedData).toEqual(INITIAL_DATA);
	//	cb();
	//});
  //
	//it('using keys "RSA_8192" with password', async (cb) => {
	//	let decryptedData = await encryptDecryptUsingKeyPair(INITIAL_DATA, VirgilCrypto.KeysTypesEnum.RSA_8192, PASSWORD);
	//	expect(decryptedData.toString('utf8')).toEqual(INITIAL_DATA);
	//	cb();
	//});

});
