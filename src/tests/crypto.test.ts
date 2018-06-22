import { VirgilCrypto, HashAlgorithm } from '../index';
import { IVirgilCrypto, VirgilPublicKey } from '../interfaces';

// private key with password = "1234"
const PRIVATE_KEY_1234 = 'LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS' +
	'0tLQpNSUdoTUYwR0NTcUdTSWIzRFFFRkRUQlFNQzhHQ1NxR1NJYjNEUUVGRERBaUJ' +
	'CQlVZWXNvUWVvTm9YSWQxVzZHCjJxN2xBZ0lUN3pBS0JnZ3Foa2lHOXcwQ0NqQWRC' +
	'Z2xnaGtnQlpRTUVBU29FRUpQSnJPZEtCdHNFZWdjTzc3dTEKTzZNRVFFVWlKTWtGT' +
	'npNck1sUjh6N0ZDVVZieDdaRkhENjJYdHI3bm5sU05VaG04V1U0L1ZqTHAwTk5xdE' +
	'RLTApPMjROaEcwa05iZUZaOXFlaFlUcU1sUXp3ejQ9Ci0tLS0tRU5EIEVOQ1JZUFR' +
	'FRCBQUklWQVRFIEtFWS0tLS0tCg==';

// public key of the above private key
const PUBLIC_KEY_1234 = 'MCowBQYDK2VwAyEAmBZSnO/w/xhO8bb+NV/xykZp42pyty+' +
	'dbsphBKdEYqA=';

// private key with password = "4321"
const PRIVATE_KEY_4321 = 'LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVk' +
	'tLS0tLQpNSUdoTUYwR0NTcUdTSWIzRFFFRkRUQlFNQzhHQ1NxR1NJYjNEUUVGRERB' +
	'aUJCQk5sMXEzeHBMTEh6Q2E5ODBMClVlMXdBZ0lPNGpBS0JnZ3Foa2lHOXcwQ0NqQ' +
	'WRCZ2xnaGtnQlpRTUVBU29FRU5XZGxvK1hnNnJqYmdIUEJPMXoKRG9nRVFBZDY3eC' +
	'tBT2xrTzBYTDNKbUEvSU5wUXE4cmNtVzU0citSUTBRY0xaaGVUdU9QYXBnZEk4UGp' +
	'Kb0ZuWQpTUVp0WjRYby9TRllOeFdUZzk3Zi94V05SZmc9Ci0tLS0tRU5EIEVOQ1JZ' +
	'UFRFRCBQUklWQVRFIEtFWS0tLS0tCg==';

// public key of the above private key
const PUBLIC_KEY_4321 = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JR' +
	'WURLMlZ3QXlFQWNCTG1pZTFKam0rRC9BM0lQdVJVSUFsK0MvUlF0RWQ1cnhmb1BEM' +
	'FlGbDQ9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=';

describe('VirgilCrypto', function () {
	let crypto: IVirgilCrypto;
	beforeEach(function () {
		crypto = new VirgilCrypto();
	});

	it('sign then encrypt -> decrypt then verify', function () {
		const senderPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_1234, '1234');
		const senderPublicKey = crypto.importPublicKey(PUBLIC_KEY_1234);

		const recipientPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_4321, '4321');
		const recipientPublicKey = crypto.importPublicKey(PUBLIC_KEY_4321);

		const message = 'Secret message';

		const cipherData = crypto.signThenEncrypt(
			message,
			senderPrivateKey,
			recipientPublicKey
		);

		const decryptedMessage = crypto.decryptThenVerify(
			cipherData,
			recipientPrivateKey,
			senderPublicKey
		);

		assert.equal(decryptedMessage.toString(), message, 'decrypted and original messages match');
	});

	it('sign and verify strings', function () {
		const data = JSON.stringify({ name: 'Default name' });

		const senderPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_1234, '1234');
		const senderPublicKey = crypto.importPublicKey(PUBLIC_KEY_1234);

		const signature = crypto.calculateSignature(data, senderPrivateKey).toString('base64');
		const isValid = crypto.verifySignature(data, signature, senderPublicKey);
		assert.isTrue(isValid, 'Verifies signature when passed string inputs');
	});

	it('encrypt and decrypt strings', function () {
		const data = JSON.stringify({ name: 'Default name' });

		const recipientPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_4321, '4321');
		const recipientPublicKey = crypto.importPublicKey(PUBLIC_KEY_4321);

		const cipherData = crypto.encrypt(data, recipientPublicKey).toString('base64');
		const decryptedData = crypto.decrypt(cipherData, recipientPrivateKey);

		assert.equal(decryptedData.toString(), data, 'Decrypts data when passed string inputs');
	});

	it('export private key without password', function () {
		const privateKeyBase64 = 'MC4CAQAwBQYDK2VwBCIEIEoWpq/k3bzUkV9ci7CGwkD8mpD480CVb1biGvEpmSvB';

		const importedKey = crypto.importPrivateKey(privateKeyBase64);
		const exportedKey = crypto.exportPrivateKey(importedKey);

		assert.equal(
			exportedKey.toString('base64'),
			privateKeyBase64,
			'exported key is equal to imported one'
		);
	});

	it('extract public key', function () {
		const privateKeyBase64 = 'MC4CAQAwBQYDK2VwBCIEIEoWpq/k3bzUkV9ci7CGwkD8mpD480CVb1biGvEpmSvB';
		const publicKeyBase64 = 'MCowBQYDK2VwAyEA9OX9DOZ70JRq4RWNIhGDkmY4fGmip6GdV/VR3R6hmIQ=';

		const privateKey = crypto.importPrivateKey(privateKeyBase64);
		const publicKey = crypto.extractPublicKey(privateKey);
		const pubkeyData = crypto.exportPublicKey(publicKey);

		assert.equal(
			pubkeyData.toString('base64'),
			publicKeyBase64,
			'extracted public key is equal to pre-computed'
		);
	});

	it('sign then encrypt -> decrypt then verify multiple public keys', function () {
		const senderPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_1234, '1234');
		const senderPublicKey = crypto.importPublicKey(PUBLIC_KEY_1234);

		const recipientPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_4321, '4321');
		const recipientPublicKey = crypto.importPublicKey(PUBLIC_KEY_4321);

		const otherPublicKey = crypto.importPublicKey(
			'MCowBQYDK2VwAyEAMiGqjvwO+0atRWjXVFEybGooQcpJO54CmJPMp66WmsU='
		);

		const message = 'Secret message';

		const cipherData = crypto.signThenEncrypt(
			message,
			senderPrivateKey,
			[ otherPublicKey, recipientPublicKey ]
		);

		const decryptedMessage = crypto.decryptThenVerify(
			cipherData,
			recipientPrivateKey,
			[ otherPublicKey, senderPublicKey ]
		);

		assert.equal(decryptedMessage.toString(), message, 'decrypted and original messages match');
	});

	it('sign then encrypt -> decrypt then verify wrong public key', function () {
		const senderPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_1234, '1234');
		const recipientPrivateKey = crypto.importPrivateKey(PRIVATE_KEY_4321, '4321');
		const recipientPublicKey = crypto.importPublicKey(PUBLIC_KEY_4321);

		const otherPublicKey = crypto.importPublicKey(
			'MCowBQYDK2VwAyEAMiGqjvwO+0atRWjXVFEybGooQcpJO54CmJPMp66WmsU='
		);

		const anotherPublicKey = crypto.importPublicKey(
			'MCowBQYDK2VwAyEAylmHyTGVh/E3RrarH359UhrHO7z+DguXJoueYLiF5VU='
		);

		const message = 'Secret message';

		const cipherData = crypto.signThenEncrypt(
			message,
			senderPrivateKey,
			[ recipientPublicKey, otherPublicKey, anotherPublicKey ]
		);

		assert.throws(function () {
				crypto.decryptThenVerify(
					cipherData,
					recipientPrivateKey,
					[ otherPublicKey, anotherPublicKey ]
				);
			},
			/Signature verification has failed/,
			'verification failed without the right public key'
		);
	});

	it('verify throws when passed invalid value as signature', function () {
		const publicKey = crypto.importPublicKey(
			'MCowBQYDK2VwAyEAMiGqjvwO+0atRWjXVFEybGooQcpJO54CmJPMp66WmsU='
		);

		assert.throws(function () {
				crypto.verifySignature('some message', undefined!, publicKey)
			},
			/Cannot verify signature/,
			'throws when invalid value for signature is passed'
		);
	});

	it('encrypt should throw when passed empty array of recipients', function () {
		const recipients: VirgilPublicKey[] = [];

		assert.throws(function () {
			crypto.encrypt('secret message', recipients);
		},/`publicKey` must not be empty/);
	});

	it('uses SHA512 identifiers by default', function () {
		const keypair = crypto.generateKeys();
		const publicKeyDer = crypto.exportPublicKey(keypair.publicKey);
		const publicKeyHash = crypto.calculateHash(publicKeyDer, HashAlgorithm.SHA512);

		assert.isTrue(keypair.publicKey.identifier.equals(publicKeyHash.slice(0, 8)));
	});

	it('uses SHA256 identifiers', function () {
		const crypto256 = new VirgilCrypto({ useSha256Identifiers: true });

		const keypair = crypto256.generateKeys();
		const publicKeyDer = crypto256.exportPublicKey(keypair.publicKey);
		const publicKeyHash = crypto256.calculateHash(publicKeyDer, HashAlgorithm.SHA256);

		assert.isTrue(keypair.publicKey.identifier.equals(publicKeyHash));
	});
});
