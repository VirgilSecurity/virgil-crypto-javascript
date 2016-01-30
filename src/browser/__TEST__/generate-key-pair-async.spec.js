import { VirgilCrypto } from '../../../browser';

const KEYS_TYPES_ENUM = VirgilCrypto.KeysTypesEnum;
const PASSWORD = 'veryStrongPa$$0rd';

describe('generaKeyPairAsync', () => {
	let keyPair = {};

	describe('with default params', () => {
		beforeEach(async (cb) => {
			keyPair = await VirgilCrypto.generateKeyPairAsync();
			cb();
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" is not encrypted', () => {
			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
		});
	});

	describe('with password', () => {
		beforeEach(async (cb) => {
			keyPair = await VirgilCrypto.generateKeyPairAsync(PASSWORD);
			cb();
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey).toContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default"', () => {
		beforeEach(async (cb) => {
			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.Default);
			cb();
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
		});
	});

	describe('with specific type "Default" and password', () => {
		beforeEach(async (cb) => {
			keyPair = await VirgilCrypto.generateKeyPairAsync(PASSWORD, KEYS_TYPES_ENUM.Default);
			cb();
		});

		it('"publicKey" should be defined', () => {
			expect(keyPair.publicKey).toBeDefined();
		});

		it('"privateKey" should be defined', () => {
			expect(keyPair.privateKey).toBeDefined();
		});

		it('"privateKey" encrypted', () => {
			expect(keyPair.privateKey).toContain('ENCRYPTED');
		});
	});

	//describe('with specific type', () => {
	//	describe(`"${KEYS_TYPES_ENUM.Default}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.Default);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_BP256R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_BP256R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_BP384R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_BP384R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_BP512R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_BP512R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_M221}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_M221);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_M255}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_M255);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_M383}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_M383);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_M511}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_M511);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP192K1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP192K1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP192R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP192R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP224K1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP224K1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP224R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP224R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP256K1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP256K1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP256R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP256R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP384R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP384R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.EC_SECP521R1}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.EC_SECP521R1);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.RSA_256}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.RSA_256);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.RSA_512}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.RSA_512);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.RSA_1024}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.RSA_1024);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.RSA_2048}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.RSA_2048);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.RSA_3072}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.RSA_3072);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.RSA_4096}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.RSA_4096);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
  //
	//	describe(`"${KEYS_TYPES_ENUM.RSA_8192}"`, () => {
	//		beforeEach(async (cb) => {
	//			keyPair = await VirgilCrypto.generateKeyPairAsync(KEYS_TYPES_ENUM.RSA_8192);
	//			cb();
	//		});
  //
	//		it('`publicKey` should be defined', () => {
	//			expect(keyPair.publicKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` should be defined', () => {
	//			expect(keyPair.privateKey).toBeDefined();
	//		});
  //
	//		it('`privateKey` not encrypted', () => {
	//			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
	//		});
	//	});
	//});

});
