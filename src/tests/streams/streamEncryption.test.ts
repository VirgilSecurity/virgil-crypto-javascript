import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilStreamCipher } from '../../streams/VirgilStreamCipher';
import { VirgilStreamDecipher } from '../../streams/VirgilStreamDecipher';
import { VirgilPublicKey } from '../../VirgilPublicKey';
import { VirgilPrivateKey } from '../../VirgilPrivateKey';
import { splitIntoChunks, createAsyncIterable } from './utils';

const CHUNK_SIZE = 65536;

describe.only ('stream encryption', function () {
	this.timeout(20 * 1000);

	it ('encrypts data', async () => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const streamCipher = new VirgilStreamCipher(
			new VirgilPublicKey(keyPairId, keyPair.publicKey)
		);

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
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const streamCipher = new VirgilStreamCipher(
			new VirgilPublicKey(keyPairId, keyPair.publicKey)
		);

		const streamDecipher = new VirgilStreamDecipher(
			new VirgilPrivateKey(keyPairId, keyPair.privateKey)
		);

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

		const initialEncryptedChunk = cipher.start();

		assert.throws(() => {
			decipher.update(initialEncryptedChunk)
		}, /recipient with given identifier is not found/i);
	});

	it ('encrypt as stream -> decrypt synchronously', async () => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const cipher = new VirgilStreamCipher(new VirgilPublicKey(keyPairId, keyPair.publicKey));
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
			{ identifier: keyPairId, key: keyPair.privateKey }
		);
		assert.isTrue(decryptedData.equals(input));
	});

	it ('encrypt synchronously -> decrypt as stream', async () => {
		const keyPair = cryptoWrapper.generateKeyPair();
		const keyPairId = Buffer.from('key_pair_id');

		const decipher = new VirgilStreamDecipher(new VirgilPrivateKey(keyPairId, keyPair.privateKey ));

		const input = Buffer.alloc(1000 * 1000).fill('foo');
		const encryptedData = cryptoWrapper.encrypt(input, { identifier: keyPairId, key: keyPair.publicKey });
		const encryptedChunks = splitIntoChunks(encryptedData, CHUNK_SIZE);

		const decryptedChunks: Buffer[] = [];

		for await (const encryptedChunk of createAsyncIterable(encryptedChunks)) {
			decryptedChunks.push(decipher.update(encryptedChunk));
		}

		decryptedChunks.push(decipher.final());
		assert.isTrue(Buffer.concat(decryptedChunks).equals(input));
	});
});
