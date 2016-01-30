import { VirgilCrypto } from '../../../browser';

const KEYS_TYPES_ENUM = VirgilCrypto.KeysTypesEnum;
const PASSWORD = 'veryStrongPa$$0rd';

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
			expect(keyPair.privateKey).not.toContain('ENCRYPTED');
		});
	});

	describe('with password', () => {
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair(PASSWORD);
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
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.Default);
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
		beforeEach(() => {
			keyPair = VirgilCrypto.generateKeyPair(PASSWORD, KEYS_TYPES_ENUM.Default);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.Default);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_BP256R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_BP384R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_BP512R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_M221);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_M255);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_M383);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_M511);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP192K1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP192R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP224K1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP224R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP256K1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP256R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP384R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.EC_SECP521R1);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.RSA_256);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.RSA_512);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.RSA_1024);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.RSA_2048);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.RSA_3072);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.RSA_4096);
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
	//		beforeAll(() => {
	//			keyPair = VirgilCrypto.generateKeyPair(KEYS_TYPES_ENUM.RSA_8192);
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
