import { cryptoWrapper } from '../node/wrapper';
import { KeyPairType } from '../common';

const PASSWORD = Buffer.from('veryStrongPa$$0rd');
const PLAINTEXT = Buffer.from('Plaintext secret message');

describe('encrypt/decrypt', function () {
	this.timeout(180 * 1000);

	function encryptDecryptUsingKeyPair(data: Buffer, keysType: KeyPairType, password?: Buffer) {
		const keyPair = cryptoWrapper.generateKeyPair({ password: password, type: keysType });
		const encryptedData = cryptoWrapper.encrypt(data, {
			key: keyPair.publicKey,
			identifier: keyPair.publicKey
		});
		return cryptoWrapper.decrypt(encryptedData, {
			identifier: keyPair.publicKey,
			key: keyPair.privateKey,
			password: password
		});
	}

	it('using password', function () {
		const encryptedData = cryptoWrapper.encryptWithPassword(PLAINTEXT, PASSWORD);
		const decryptedData = cryptoWrapper.decryptWithPassword(encryptedData, PASSWORD);
		assert.isFalse(encryptedData.equals(PLAINTEXT), 'data is encrypted');
		assert.isTrue(decryptedData.equals(PLAINTEXT), 'data is decrypted ');
	});

	Object.keys(KeyPairType)
		.filter(function (keyType) {
			// these take too long to generate and encrypt causing the test
			// to fail by timeout
			if (process.browser) {
				return keyType.indexOf('RSA') !== 0;
			}

			return keyType !== 'RSA_8192';
		})
		.forEach(function (keyType) {
			it('using keys \''+keyType+'\' without password', function () {
				const decryptedData = encryptDecryptUsingKeyPair(
					PLAINTEXT, KeyPairType[keyType as KeyPairType]
				);
				assert.isTrue(decryptedData.equals(PLAINTEXT));
			});

			it('using keys \''+keyType+'\' with password', function () {
				const decryptedData = encryptDecryptUsingKeyPair(
					PLAINTEXT, KeyPairType[keyType as KeyPairType], PASSWORD
				);
				assert.isTrue(decryptedData.equals(PLAINTEXT));
			});
		});

	it('should encrypt and decrypt data for multiple recipients', function () {
		const numRecipients = 3;
		const recipients = [];
		let keyPair;
		for (let i = 0; i < numRecipients; i++) {
			keyPair = cryptoWrapper.generateKeyPair();
			recipients.push({
				identifier: cryptoWrapper.hash(keyPair.publicKey),
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			});
		}

		const encryptedData = cryptoWrapper.encrypt(PLAINTEXT, recipients.map(r => ({
			key: r.publicKey,
			identifier: r.identifier
		})));

		recipients.forEach(function (r) {
			const decryptedData = cryptoWrapper.decrypt(
				encryptedData,
				{ identifier: r.identifier, key: r.privateKey }
			);
			assert.isTrue(decryptedData.equals(PLAINTEXT));
		});
	});
});
