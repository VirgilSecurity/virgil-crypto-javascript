import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilStreamSigner } from '../../streams/VirgilStreamSigner';
import { VirgilStreamVerifier } from '../../streams/VirgilStreamVerifier';
import { VirgilPrivateKey } from '../../VirgilPrivateKey';
import { VirgilPublicKey } from '../../VirgilPublicKey';
import { createAsyncIterable, splitIntoChunks, createVirgilKeyPair } from './utils';
import { VirgilStreamCipher } from '../../streams/VirgilStreamCipher';
import { VirgilStreamDecipher } from '../../streams/VirgilStreamDecipher';
import { StringEncoding } from '../../utils/anyToBuffer';

const CHUNK_SIZE = 65536;

describe('stream signing', function() {
	this.timeout(30 * 1000);

	describe('signature calculation', () => {
		it('calculates the signature', async () => {
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

	describe('transfer the signature', () => {
		let publicKey: VirgilPublicKey;
		let privateKey: VirgilPrivateKey;
		let signature: Buffer;
		let inputChunks: Buffer[];

		beforeEach(async () => {
			({ privateKey, publicKey } = createVirgilKeyPair());
			const streamSigner = new VirgilStreamSigner();
			const input = Buffer.alloc(3 * 1000).fill('foo');
			inputChunks = splitIntoChunks(input, CHUNK_SIZE);

			for await (const chunk of createAsyncIterable(inputChunks)) {
				streamSigner.update(chunk);
			}

			signature = streamSigner.sign(privateKey);
		});

		const transferSignature = async (encoding?: StringEncoding) => {
			assert.isTrue(Buffer.isBuffer(signature));

			const streamCipher = new VirgilStreamCipher(
				publicKey,
				encoding ? signature.toString(encoding) : signature,
				encoding
			);
			const encryptedBuffer: Buffer[] = [];

			encryptedBuffer.push(streamCipher.start());

			for await (const chunk of createAsyncIterable(inputChunks)) {
				encryptedBuffer.push(streamCipher.update(chunk));
			}
			encryptedBuffer.push(streamCipher.final());

			const streamDecipher = new VirgilStreamDecipher(privateKey);
			const decryptedBuffer: Buffer[] = [];

			for await (const chunk of createAsyncIterable(encryptedBuffer)) {
				decryptedBuffer.push(streamDecipher.update(chunk));
			}

			decryptedBuffer.push(streamDecipher.final(false));
			let transferredSignature: Buffer | string = streamDecipher.getSignature()!;
			if (encoding) transferredSignature = transferredSignature.toString(encoding);
			streamDecipher.dispose();
			assert.exists(transferredSignature);
			const streamVerifier = new VirgilStreamVerifier(transferredSignature!, encoding);

			for await (const chunk of createAsyncIterable(inputChunks)) {
				streamVerifier.update(chunk);
			}

			encoding
				? assert.isString(transferredSignature)
				: assert.isTrue(Buffer.isBuffer(transferredSignature));

			return streamVerifier.verify(publicKey);
		};

		it('transfer base64 signature', async () => {
			const isVerified = await transferSignature('base64');
			assert.isTrue(isVerified);
		});

		it('transfer buffer signature', async () => {
			const isVerified = await transferSignature();
			assert.isTrue(isVerified);
		});
	});

	describe('signature verification', () => {
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
