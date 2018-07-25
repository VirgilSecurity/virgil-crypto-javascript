import { cryptoWrapper } from '../virgilCryptoWrapper';
import { KeyPairType } from '../common';

function getRandomBytes (length: number) {
	if (process.browser) {
		return Buffer.from((window.crypto.getRandomValues(new Uint8Array(length))!).buffer as ArrayBuffer);
	} else {
		return require('crypto').randomBytes(length);
	}
}

const PASSWORD = Buffer.from('veryStrongPa$$0rd');
const SEED = getRandomBytes(64);

describe ('generateKeyPairFromKeyMaterial',  () => {

	it ('with default params', () =>  {
		const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({ keyMaterial: SEED });
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it ('with password', () => {
		const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({
			keyMaterial: SEED,
			password: PASSWORD
		});
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'), 'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it ('with specific type "Default"',  () => {
		const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({
			keyMaterial: SEED,
			type: KeyPairType.Default
		});
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it ('with specific type "Default" and password', () => {
		const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({
			keyMaterial: SEED,
			password: PASSWORD,
			type: KeyPairType.Default
		});
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it ('with specific type EC_SECP384R1', () => {
		const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({
			keyMaterial: SEED,
			type: KeyPairType.EC_SECP384R1
		});
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.notInclude(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is not encrypted'
		);
	});

	it ('with specific type EC_SECP384R1 and password', () => {
		const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({
			keyMaterial: SEED,
			type: KeyPairType.EC_SECP384R1,
			password: PASSWORD
		});
		assert.exists(keyPair.publicKey, 'publicKey is defined');
		assert.exists(keyPair.privateKey, 'privateKey is defined');
		assert.include(
			keyPair.privateKey.toString('utf8'),
			'ENCRYPTED',
			'privateKey is encrypted'
		);
	});

	it ('generates the same keys from the same seed', () => {
		const seed = getRandomBytes(64);

		const keyPair1 = cryptoWrapper.generateKeyPairFromKeyMaterial({ keyMaterial: seed });
		const keyPair2 = cryptoWrapper.generateKeyPairFromKeyMaterial({ keyMaterial: seed });

		assert.isTrue(keyPair1.privateKey.equals(keyPair2.privateKey));
	});

	it ('generates different keys from different seeds', () => {
		const seed1 = getRandomBytes(32);
		const seed2 = getRandomBytes(32);

		const keyPair1 = cryptoWrapper.generateKeyPairFromKeyMaterial({ keyMaterial: seed1 });
		const keyPair2 = cryptoWrapper.generateKeyPairFromKeyMaterial({ keyMaterial: seed2 });

		assert.isFalse(keyPair1.privateKey.equals(keyPair2.privateKey));
	});

	it ('throws when key material is weak (with recommended type)', () => {
		const weakSeed = Buffer.from('weak_key_pair_seed');

		assert.throws(() => {
			cryptoWrapper.generateKeyPairFromKeyMaterial({ keyMaterial: weakSeed });
		}, /key material is not secure/i);
	});

	it ('throws when key material is weak (with custom type)', () => {
		const weakSeed = Buffer.from('weak_key_pair_seed');

		assert.throws(() => {
			cryptoWrapper.generateKeyPairFromKeyMaterial({
				keyMaterial: weakSeed,
				type: KeyPairType.EC_SECP256R1
			});
		}, /key material is not secure/i);
	});
});
