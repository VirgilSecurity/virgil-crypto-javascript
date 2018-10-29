import { VirgilStreamVerifier } from '../../streams/VirgilStreamVerifier';
import { VirgilStreamSigner } from '../../streams/VirgilStreamSigner';
import { createVirgilKeyPair } from './utils';

describe ('VrigilStreamVerifier', () => {
	describe ('constructor', () => {
		it ('requires signature', () => {
			assert.throws(() => {
				new VirgilStreamVerifier(undefined!)
			}, 'Expected `signature`');
		});
	});

	if (process.browser) {
		it ('verify cannot be called more than once by default', () => {
			const keyPair = createVirgilKeyPair();
			const input = Buffer.alloc(1000).fill('foo');

			const streamSigner = new VirgilStreamSigner();
			streamSigner.update(input);
			const signature = streamSigner.sign(keyPair.privateKey);

			const streamVerifier = new VirgilStreamVerifier(signature);
			streamVerifier.update(input);
			streamVerifier.verify(keyPair.publicKey);

			const anotherKeyPair = createVirgilKeyPair();
			assert.throws(() => {
				streamVerifier.verify(anotherKeyPair.publicKey);
			}, 'Illegal state');
		});

		it ('verify can be called more that once of `final` is `false`', () => {
			const keyPair = createVirgilKeyPair();
			const input = Buffer.alloc(1000).fill('foo');

			const streamSigner = new VirgilStreamSigner();
			streamSigner.update(input);
			const signature = streamSigner.sign(keyPair.privateKey);

			const streamVerifier = new VirgilStreamVerifier(signature);
			streamVerifier.update(input);
			streamVerifier.verify(keyPair.publicKey, false);

			const anotherKeyPair = createVirgilKeyPair();
			assert.doesNotThrow(() => {
				streamVerifier.verify(anotherKeyPair.publicKey);
			});
		});

		it ('verifier update cannot be called if dispose was called', () => {
			const keyPair = createVirgilKeyPair();
			const input = Buffer.alloc(1000).fill('foo');

			const streamSigner = new VirgilStreamSigner();
			streamSigner.update(input);
			const signature = streamSigner.sign(keyPair.privateKey);

			const streamVerifier = new VirgilStreamVerifier(signature);
			streamVerifier.dispose();
			assert.throws(() => {
				streamVerifier.update(input);
			}, 'Illegal state');
		});
	}
});
