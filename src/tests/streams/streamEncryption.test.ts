import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilStreamCipher } from '../../streams/VirgilStreamCipher';
import { VirgilStreamDecipher } from '../../streams/VirgilStreamDecipher';
import { VirgilPublicKey } from '../../VirgilPublicKey';
import { VirgilPrivateKey } from '../../VirgilPrivateKey';
import { writeToStreamInChunks, readableStreamToPromise } from './utils';

describe ('VirgilStreamCipher', () => {
	describe ('constructor', () => {
		it ('validates public keys', () => {
			const invalidPublicKey = {} as VirgilPublicKey;
			assert.throws(
				() => new VirgilStreamCipher(invalidPublicKey),
				TypeError
			);
		});
	});
});

describe ('VirgilStreamDecipher', () => {
	describe('constructor', () => {
		it ('validates private key', () => {
			const invalidPrivateKey = {} as VirgilPrivateKey;
			assert.throws(
				() => new VirgilStreamDecipher(invalidPrivateKey),
				TypeError
			);
		});
	});
});

describe.only ('stream encryption', function () {
	this.timeout(15 * 1000);

	it ('encrypts data', (done) => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const streamCipher = new VirgilStreamCipher(
			new VirgilPublicKey(keyPairId, keyPair.publicKey)
		);

		const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');

		writeToStreamInChunks(streamCipher, input);

		readableStreamToPromise(streamCipher)
		.then(encrypted => {
			assert.isFalse(encrypted.equals(input));
			done();
		})
		.catch(err => done(err));
	});

	it ('decrypts data', (done) => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const streamCipher = new VirgilStreamCipher(
			new VirgilPublicKey(keyPairId, keyPair.publicKey)
		);

		const streamDecipher = new VirgilStreamDecipher(
			new VirgilPrivateKey(keyPairId, keyPair.privateKey)
		);

		const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');

		streamCipher.pipe(streamDecipher);

		writeToStreamInChunks(streamCipher, input);

		readableStreamToPromise(streamDecipher)
		.then(decrypted => {
			assert.isTrue(decrypted.equals(input));
			done();
		})
		.catch(err => done(err));
	});

	it ('encrypts and decrypts with multiple keys', (done) => {
		const keyPair1 = cryptoWrapper.generateKeyPair();
		const keyPairId1 = Buffer.from('key_pair_id_1');

		const keyPair2 = cryptoWrapper.generateKeyPair();
		const keyPairId2 = Buffer.from('key_pair_id_2');

		const cipher = new VirgilStreamCipher(
			[
				new VirgilPublicKey(keyPairId1, keyPair1.publicKey),
				new VirgilPublicKey(keyPairId2, keyPair2.publicKey)
			]
		);

		const decipher1 = new VirgilStreamDecipher(
			new VirgilPrivateKey(keyPairId1, keyPair1.privateKey)
		);
		const decipher2 = new VirgilStreamDecipher(
			new VirgilPrivateKey(keyPairId2, keyPair2.privateKey)
		);

		const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');

		cipher.pipe(decipher1);
		cipher.pipe(decipher2);

		writeToStreamInChunks(cipher, input);

		Promise.all([
			readableStreamToPromise(decipher1),
			readableStreamToPromise(decipher2)
		]).then(([ decrypted1, decrypted2 ]) => {
			assert.isTrue(decrypted1.equals(input));
			assert.isTrue(decrypted2.equals(input));
			done();
		}).catch(err => done(err));
	});

	it ('emits error when trying to decrypt with a wrong key', (done) => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const wrongKeyPair = cryptoWrapper.generateKeyPair();
		const wrongKeyPairId = Buffer.from('wrong_key_pair_id');

		const cipher = new VirgilStreamCipher(
			new VirgilPublicKey(keyPairId, keyPair.publicKey)
		);

		const decipher = new VirgilStreamDecipher(
			new VirgilPrivateKey(wrongKeyPairId, wrongKeyPair.privateKey)
		);

		const input = Buffer.alloc(3 * 1000 * 1000).fill('bar');

		cipher.pipe(decipher);

		writeToStreamInChunks(cipher, input);

		readableStreamToPromise(decipher)
		.then(() => done(new Error('The steam should have emitted an error')))
		.catch(err => {
			if (/recipient with given identifier is not found/i.test(err.message)) {
				return done();
			}

			done(err);
		})
	});

	it ('encrypt as stream -> decrypt synchronously', done => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const cipher = new VirgilStreamCipher(new VirgilPublicKey(keyPairId, keyPair.publicKey));
		const input = Buffer.alloc(1000 * 1000).fill('foo');

		let ciphertext = Buffer.alloc(0);
		cipher.on('readable', () => {
			const data = cipher.read();
			if (data) {
				ciphertext = Buffer.concat([ciphertext, data]);
			}
		});

		cipher.on('end', () => {
			const decryptedData = cryptoWrapper.decrypt(ciphertext, { identifier: keyPairId, key: keyPair.privateKey });
			assert.deepEqual(decryptedData, input);
			done();
		});

		cipher.on('error', err => {
			done(err);
		});

		cipher.write(input);
		cipher.end();
	});

	it ('encrypt synchronously -> decrypt as stream', done => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const input = Buffer.alloc(1000 * 1000).fill('foo');
		const ciphertext = cryptoWrapper.encrypt(input, { identifier: keyPairId, key: keyPair.publicKey });

		const decipher = new VirgilStreamDecipher(new VirgilPrivateKey(keyPairId, keyPair.privateKey ));

		let plaintext = Buffer.alloc(0);

		decipher.on('readable', () => {
			const data = decipher.read();
			if (data) {
				plaintext = Buffer.concat([ plaintext, data ]);
			}
		});

		decipher.on('error', err => {
			done(err);
		});

		decipher.on('end', () => {
			assert.deepEqual(plaintext, input);
			done();
		});

		decipher.write(ciphertext);
		decipher.end();
	});
});
