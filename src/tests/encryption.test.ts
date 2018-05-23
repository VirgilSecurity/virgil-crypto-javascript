import { cryptoApi } from '../node/api';
import { KeyPairType } from '../common';

const PASSWORD = Buffer.from('veryStrongPa$$0rd');
const PLAINTEXT = Buffer.from('Plaintext secret message');

describe('encrypt/decrypt', function () {
	this.timeout(120 * 1000);

	function encryptDecryptUsingKeyPair(data: Buffer, keysType: KeyPairType, password?: Buffer) {
		const keyPair = cryptoApi.generateKeyPair({ password: password, type: keysType });
		const encryptedData = cryptoApi.encrypt(data, {
			key: keyPair.publicKey,
			identifier: keyPair.publicKey
		});
		return cryptoApi.decrypt(encryptedData, {
			identifier: keyPair.publicKey,
			key: keyPair.privateKey,
			password: password
		});
	}

	it('using password', function () {
		const encryptedData = cryptoApi.encryptWithPassword(PLAINTEXT, PASSWORD);
		const decryptedData = cryptoApi.decryptWithPassword(encryptedData, PASSWORD);
		assert.isFalse(encryptedData.equals(PLAINTEXT), 'data is encrypted');
		assert.isTrue(decryptedData.equals(PLAINTEXT), 'data is decrypted ');
	});

	Object.keys(KeyPairType)
		.filter(function (keyType) {
			// these take too long to generate and encrypt causing the test
			// to fail by timeout
			return keyType !== 'RSA_8192' && keyType !== 'RSA_4096';
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
			keyPair = cryptoApi.generateKeyPair();
			recipients.push({
				identifier: cryptoApi.hash(keyPair.publicKey),
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			});
		}

		const encryptedData = cryptoApi.encrypt(PLAINTEXT, recipients.map(r => ({
			key: r.publicKey,
			identifier: r.identifier
		})));

		recipients.forEach(function (r) {
			const decryptedData = cryptoApi.decrypt(
				encryptedData,
				{ identifier: r.identifier, key: r.privateKey }
			);
			assert.isTrue(decryptedData.equals(PLAINTEXT));
		});
	});
});
