import { cryptoWrapper } from '../virgilCryptoWrapper';
import { VirgilStreamCipher, VirgilStreamDecipher } from '../stream-encryption';
import { VirgilPublicKey } from '../VirgilPublicKey';
import { WrappedVirgilSeqCipher } from '../common';
import { VirgilPrivateKey } from '../VirgilPrivateKey';

describe ('VirgilStreamCipher', () => {
	describe ('constructor', () => {
		it ('validates public keys', () => {
			const invalidPublicKey = {} as VirgilPublicKey;
			const seqCipherStub = {} as WrappedVirgilSeqCipher;
			assert.throws(
				() => new VirgilStreamCipher(seqCipherStub, invalidPublicKey),
				TypeError
			);
		});
	});
});

describe ('VirgilStreamDecipher', () => {
	describe('constructor', () => {
		it ('validates private key', () => {
			const invalidPrivateKey = {} as VirgilPrivateKey;
			const seqCipherStub = {} as WrappedVirgilSeqCipher;
			assert.throws(
				() => new VirgilStreamDecipher(seqCipherStub, invalidPrivateKey),
				TypeError
			);
		});
	});
});

describe ('stream encryption', function () {
	this.timeout(10 * 1000);

	it ('encrypts data', (done) => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const streamCipher = new VirgilStreamCipher(
			cryptoWrapper.createVirgilSeqCipher(),
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
			cryptoWrapper.createVirgilSeqCipher(),
			new VirgilPublicKey(keyPairId, keyPair.publicKey)
		);

		const streamDecipher = new VirgilStreamDecipher(
			cryptoWrapper.createVirgilSeqCipher(),
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
			cryptoWrapper.createVirgilSeqCipher(),
			[
				new VirgilPublicKey(keyPairId1, keyPair1.publicKey),
				new VirgilPublicKey(keyPairId2, keyPair2.publicKey)
			]
		);

		const decipher1 = new VirgilStreamDecipher(
			cryptoWrapper.createVirgilSeqCipher(),
			new VirgilPrivateKey(keyPairId1, keyPair1.privateKey)
		);
		const decipher2 = new VirgilStreamDecipher(
			cryptoWrapper.createVirgilSeqCipher(),
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

	it.only ('emits error when trying to decrypt with a wrong key', (done) => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const wrongKeyPair = cryptoWrapper.generateKeyPair();
		const wrongKeyPairId = Buffer.from('wrong_key_pair_id');

		const cipher = new VirgilStreamCipher(
			cryptoWrapper.createVirgilSeqCipher(),
			new VirgilPublicKey(keyPairId, keyPair.publicKey)
		);

		const decipher = new VirgilStreamDecipher(
			cryptoWrapper.createVirgilSeqCipher(),
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
});

function readableStreamToPromise(readable: NodeJS.ReadableStream): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		readable.on('readable', () => {
			const data = readable.read();
			if (data) {
				chunks.push(data as Buffer);
			}
		});

		readable.on('close', () => {
			console.log('READABLE CLOSED');
		});

		readable.on('error', err => {
			reject(err);
		});

		readable.on('end', () => {
			resolve(Buffer.concat(chunks));
		});
	});
}

function writeToStreamInChunks(writable: NodeJS.WritableStream, input: Buffer) {
	const CHUNK_SIZE = 1024 * 1024; // 1Mb
	const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

	function next() {
		if (inputChunks.length > 0) {
			writable.write(inputChunks.shift() as Buffer);
			setTimeout(next, 0);
		} else {
			writable.end();
		}
	}

	next();
}

function splitIntoChunks (input: Buffer, chunkSize: number) {
	const chunks = [];
	let offset = 0;
	while(offset < input.byteLength) {
		chunks.push(input.slice(offset, offset += chunkSize));
	}
	return chunks;
}
