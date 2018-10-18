import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilStreamSigner } from '../../streams/VirgilStreamSigner';
import { VirgilStreamVerifier } from '../../streams/VirgilStreamVerifier';
import { writeToStreamInChunks, readableStreamToPromise } from './utils';
import { VirgilPrivateKey } from '../../VirgilPrivateKey';
import { VirgilPublicKey } from '../../VirgilPublicKey';

describe ('stream signing', function () {
	this.timeout(15 * 1000);

	describe ('signature calculation', () => {
		it ('using StreamSigner as stream', done => {
			const { privateKey } = createVirgilKeyPair();
			const streamSigner = new VirgilStreamSigner();
			const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');

			writeToStreamInChunks(streamSigner, input);

			readableStreamToPromise(streamSigner)
			.then(transformedInput => {
				assert.isTrue(transformedInput.equals(input), 'does not modify input');
				const signature = streamSigner.sign(privateKey);

				assert.isTrue(Buffer.isBuffer(signature), 'calculates the signature');
				done();
			})
			.catch(err => done(err));
		});

		it ('using update and sign methods', () => {
			const { privateKey } = createVirgilKeyPair();
			const streamSigner = new VirgilStreamSigner();
			const inputs = [
				Buffer.alloc(1000 * 1000).fill('foo'),
				Buffer.alloc(1000 * 1000).fill('bar'),
				Buffer.alloc(1000 * 1000).fill('baz')
			];

			while (inputs.length > 0) {
				streamSigner.update(inputs.pop() as Buffer);
			}

			const signature = streamSigner.sign(privateKey);
			assert.isTrue(Buffer.isBuffer(signature), 'calculates the signature');
		});
	});

	describe ('signature verification', () => {
		it ('using StreamVerifier as stream', done => {
			const keyPair = createVirgilKeyPair();
			const streamSigner = new VirgilStreamSigner();
			const input = Buffer.alloc(5 * 1000 * 1000).fill('foo');

			writeToStreamInChunks(streamSigner, input);

			readableStreamToPromise(streamSigner)
			.then(_ => {
				const signature = streamSigner.sign(keyPair.privateKey);
				const streamVerifier = new VirgilStreamVerifier(signature);

				writeToStreamInChunks(streamVerifier, input);

				return readableStreamToPromise(streamVerifier).then(transformedInput => {
					assert.isTrue(transformedInput.equals(input), 'does not modify input');
					assert.isTrue(streamVerifier.verify(keyPair.publicKey), 'signature is valid');
					done();
				});
			})
			.catch(err => done(err));
		});

		it ('using update and verify methods', () => {
			const keyPair = createVirgilKeyPair();
			const streamSigner = new VirgilStreamSigner();
			const inputs = [
				Buffer.alloc(1000 * 1000).fill('foo'),
				Buffer.alloc(1000 * 1000).fill('bar'),
				Buffer.alloc(1000 * 1000).fill('baz')
			];

			streamSigner.update(inputs[0]);
			streamSigner.update(inputs[1]);
			streamSigner.update(inputs[2]);

			const signature = streamSigner.sign(keyPair.privateKey);
			const streamVerifier = new VirgilStreamVerifier(signature);

			streamVerifier.update(inputs[0]);
			streamVerifier.update(inputs[1]);
			streamVerifier.update(inputs[2]);

			assert.isTrue(streamVerifier.verify(keyPair.publicKey));
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

function createVirgilKeyPair() {
	const keyPair = cryptoWrapper.generateKeyPair();
	const keyPairId = Buffer.from('key_pair_id');
	return {
		privateKey: new VirgilPrivateKey(keyPairId, keyPair.privateKey),
		publicKey: new VirgilPublicKey(keyPairId, keyPair.publicKey)
	};
}
