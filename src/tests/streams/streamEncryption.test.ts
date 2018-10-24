import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilStreamCipher } from '../../streams/VirgilStreamCipher';
import { VirgilStreamDecipher } from '../../streams/VirgilStreamDecipher';
import { splitIntoChunks, createAsyncIterable, createVirgilKeyPair } from './utils';
import { getPrivateKeyBytes } from '../../privateKeyUtils';

const CHUNK_SIZE = 65536;

describe ('stream encryption', function () {
	this.timeout(20 * 1000);

	it ('encrypts data', async () => {
		const keyPair = createVirgilKeyPair();

		const streamCipher = new VirgilStreamCipher(keyPair.publicKey);

		const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');
		const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

		const encryptedChunks: Buffer[] = [];
		encryptedChunks.push(streamCipher.start());

		for await (const inputChunk of inputChunks) {
			encryptedChunks.push(streamCipher.update(inputChunk));
		}

		encryptedChunks.push(streamCipher.final());

		assert.isFalse(Buffer.concat(encryptedChunks).equals(input));
	});

	it ('decrypts data', async () => {
		const keyPair = createVirgilKeyPair();
		const streamCipher = new VirgilStreamCipher(keyPair.publicKey);
		const streamDecipher = new VirgilStreamDecipher(keyPair.privateKey);

		const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');
		const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

		const decryptedChunks: Buffer[] = [];
		decryptedChunks.push(streamDecipher.update(streamCipher.start()));

		for await (const inputChunk of inputChunks) {
			const encryptedChunk = streamCipher.update(inputChunk);
			decryptedChunks.push(streamDecipher.update(encryptedChunk));
		}

		decryptedChunks.push(streamDecipher.final(streamCipher.final())!);
		assert.isTrue(Buffer.concat(decryptedChunks).equals(input));
	});

	it ('encrypts and decrypts with multiple keys', async () => {
		const keyPair1 = createVirgilKeyPair();
		const keyPair2 = createVirgilKeyPair();

		const cipher = new VirgilStreamCipher(
			[
				keyPair1.publicKey,
				keyPair2.publicKey
			]
		);

		const decipher1 = new VirgilStreamDecipher(keyPair1.privateKey);
		const decipher2 = new VirgilStreamDecipher(keyPair2.privateKey);

		const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');
		const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

		const decryptedChunks1: Buffer[] = [];
		const decryptedChunks2: Buffer[] = [];

		const initialEncryptedChunk = cipher.start();
		decryptedChunks1.push(decipher1.update(initialEncryptedChunk));
		decryptedChunks2.push(decipher2.update(initialEncryptedChunk));

		for await (const inputChunk of createAsyncIterable(inputChunks)) {
			const encryptedChunk = cipher.update(inputChunk);
			decryptedChunks1.push(decipher1.update(encryptedChunk));
			decryptedChunks2.push(decipher2.update(encryptedChunk));
		}

		const finalEncryptedChunk = cipher.final();
		decryptedChunks1.push(decipher1.final(finalEncryptedChunk));
		decryptedChunks2.push(decipher2.final(finalEncryptedChunk));

		assert.isTrue(Buffer.concat(decryptedChunks1).equals(input));
		assert.isTrue(Buffer.concat(decryptedChunks2).equals(input));
	});

	it ('throws error when trying to decrypt with a wrong key', () => {
		const keyPair = createVirgilKeyPair();
		const wrongKeyPair = createVirgilKeyPair();

		const cipher = new VirgilStreamCipher(keyPair.publicKey);
		const decipher = new VirgilStreamDecipher(wrongKeyPair.privateKey);

		const initialEncryptedChunk = cipher.start();

		assert.throws(() => {
			decipher.update(initialEncryptedChunk)
		}, /recipient with given identifier is not found/i);
	});

	it ('encrypt as stream -> decrypt synchronously', async () => {
		const keyPair = createVirgilKeyPair();

		const cipher = new VirgilStreamCipher(keyPair.publicKey);
		const input = Buffer.alloc(1000 * 1000).fill('foo');
		const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

		const encryptedChunks: Buffer[] = [];
		encryptedChunks.push(cipher.start());

		for await (const inputChunk of createAsyncIterable(inputChunks)) {
			encryptedChunks.push(cipher.update(inputChunk));
		}

		encryptedChunks.push(cipher.final());
		const decryptedData = cryptoWrapper.decrypt(
			Buffer.concat(encryptedChunks),
			{ identifier: keyPair.privateKey.identifier, key: getPrivateKeyBytes(keyPair.privateKey) }
		);
		assert.isTrue(decryptedData.equals(input));
	});

	it ('encrypt synchronously -> decrypt as stream', async () => {
		const keyPair = createVirgilKeyPair();

		const decipher = new VirgilStreamDecipher(keyPair.privateKey);

		const input = Buffer.alloc(1000 * 1000).fill('foo');
		const encryptedData = cryptoWrapper.encrypt(input, keyPair.publicKey);
		const encryptedChunks = splitIntoChunks(encryptedData, CHUNK_SIZE);

		const decryptedChunks: Buffer[] = [];

		for await (const encryptedChunk of createAsyncIterable(encryptedChunks)) {
			decryptedChunks.push(decipher.update(encryptedChunk));
		}

		decryptedChunks.push(decipher.final());
		assert.isTrue(Buffer.concat(decryptedChunks).equals(input));
	});
});
