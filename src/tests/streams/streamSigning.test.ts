import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilStreamSigner } from '../../streams/VirgilStreamSigner';
import { VirgilStreamVerifier } from '../../streams/VirgilStreamVerifier';
import { VirgilPrivateKey } from '../../VirgilPrivateKey';
import { VirgilPublicKey } from '../../VirgilPublicKey';
import { createAsyncIterable, splitIntoChunks, createVirgilKeyPair } from './utils';

const CHUNK_SIZE = 65536;

describe ('stream signing', function () {
	this.timeout(10 * 1000);

	describe ('signature calculation', () => {

		it ('calulates the signature', async () => {
			const { privateKey } = createVirgilKeyPair();
			const streamSigner = new VirgilStreamSigner();
			const input = Buffer.alloc(3 * 1000 * 1000).fill('foo');
			const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

			for await (const chunk of createAsyncIterable(inputChunks)) {
				streamSigner.update(chunk);
			}

			const signature = streamSigner.sign(privateKey);
			assert.isTrue(Buffer.isBuffer(signature));
		});
	});

	describe ('signature verification', () => {

		it ('verifies the signature', async () => {
			const keyPair = createVirgilKeyPair();
			const streamSigner = new VirgilStreamSigner();
			const input = Buffer.alloc(3 * 1000 * 1000).fill('foo');
			const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

			for await (const chunk of createAsyncIterable(inputChunks)) {
				streamSigner.update(chunk);
			}

			const signature = streamSigner.sign(keyPair.privateKey);

			const streamVerifier = new VirgilStreamVerifier(signature);

			for await (const chunk of createAsyncIterable(inputChunks)) {
				streamVerifier.update(chunk);
			}

			assert.isTrue(streamVerifier.verify(keyPair.publicKey));
		});

		it ('does not verify signature given the wrong key', async () => {
			const keyPair = createVirgilKeyPair();
			const input = Buffer.alloc(3 * 1000 * 1000).fill('foo');
			const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

			const streamSigner = new VirgilStreamSigner();
			for await (const chunk of createAsyncIterable(inputChunks)) {
				streamSigner.update(chunk);
			}
			const signature = streamSigner.sign(keyPair.privateKey);

			const wrongKeyPair = createVirgilKeyPair();
			const streamVerifier = new VirgilStreamVerifier(signature);

			for await (const chunk of createAsyncIterable(inputChunks)) {
				streamVerifier.update(chunk);
			}

			assert.isFalse(streamVerifier.verify(wrongKeyPair.publicKey));
		});

		it ('sign synchronously -> verify as stream', () => {
			const keyPair = cryptoWrapper.generateKeyPair();
			const keyPairId = Buffer.from('key_pair_id');

			const input = Buffer.alloc(1000).fill('foo');
			const signature = cryptoWrapper.sign(input, { key: keyPair.privateKey });

			const streamVerifier = new VirgilStreamVerifier(signature);

			streamVerifier.update(input);
			assert.isTrue(
				streamVerifier.verify(new VirgilPublicKey(keyPairId, keyPair.publicKey))
			);
		});

		it ('sign as stream -> verify synchronously', () => {
			const keyPair = cryptoWrapper.generateKeyPair();
			const keyPairId = Buffer.from('key_pair_id');
			const streamSigner = new VirgilStreamSigner();
			const input = Buffer.alloc(1000).fill('foo');

			streamSigner.update(input);
			const signature = streamSigner.sign(new VirgilPrivateKey(keyPairId, keyPair.privateKey));

			assert.isTrue(cryptoWrapper.verify(input, signature, { key: keyPair.publicKey }));
		});
	});
});
