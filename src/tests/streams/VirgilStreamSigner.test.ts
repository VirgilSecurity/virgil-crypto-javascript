import { createVirgilKeyPair } from './utils';
import { VirgilStreamSigner } from '../../streams/VirgilStreamSigner';

describe ('VirgilStreamSigner', () => {
	if (process.browser) {
		it ('sign cannot be called more than once by default', () => {
			const keyPair = createVirgilKeyPair();
			const input = Buffer.alloc(1000).fill('foo');

			const streamSigner = new VirgilStreamSigner();
			streamSigner.update(input);

			streamSigner.sign(keyPair.privateKey);

			const anotherKeyPair = createVirgilKeyPair();
			assert.throws(() => {
				streamSigner.sign(anotherKeyPair.privateKey);
			}, 'Illegal state');
		});

		it ('sign can be called more than once if `final` is `false`', () => {
			const keyPair = createVirgilKeyPair();
			const input = Buffer.alloc(1000).fill('foo');

			const streamSigner = new VirgilStreamSigner();
			streamSigner.update(input);

			streamSigner.sign(keyPair.privateKey, false);

			const anotherKeyPair = createVirgilKeyPair();
			assert.doesNotThrow(() => {
				streamSigner.sign(anotherKeyPair.privateKey);
			});
		});

		it ('update cannot be called if dispose was called', () => {
			const input = Buffer.alloc(1000).fill('foo');

			const streamSigner = new VirgilStreamSigner();
			streamSigner.dispose();
			assert.throws(() => {
				streamSigner.update(input);
			}, 'Illegal state');
		});
	}
});
