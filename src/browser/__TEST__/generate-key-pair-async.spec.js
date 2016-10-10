import { VirgilCrypto, Buffer } from '../../../browser';

const KEYS_TYPES_ENUM = VirgilCrypto.KeysTypesEnum;
const PASSWORD = Buffer.from('veryStrongPa$$0rd');

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
			expect(keyPair.privateKey.toString('utf8')).not.toContain('ENCRYPTED');
		});
	});

	describe('with password', () => {
		beforeEach(async (cb) => {
			keyPair = await VirgilCrypto.generateKeyPairAsync({ password: PASSWORD });
			cb();
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
		beforeEach(async (cb) => {
			keyPair = await VirgilCrypto.generateKeyPairAsync({ type: KEYS_TYPES_ENUM.Default });
			cb();
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

	describe('with specific type "FAST_EC_X25519" and password', () => {
		beforeEach(async (cb) => {
			keyPair = await VirgilCrypto.generateKeyPairAsync({
				password: PASSWORD,
				type: KEYS_TYPES_ENUM.FAST_EC_X25519
			});
			cb();
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

});
