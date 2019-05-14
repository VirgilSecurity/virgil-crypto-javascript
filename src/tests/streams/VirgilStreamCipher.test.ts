import { VirgilStreamCipher } from '../../streams/VirgilStreamCipher';
import { VirgilPublicKey } from '../../VirgilPublicKey';
import { createVirgilKeyPair } from './utils';

describe ('VirgilStreamCipher', () => {
	describe ('constructor', () => {
		it ('validates public keys', () => {
			const invalidPublicKey = {} as VirgilPublicKey;
			assert.throws(
				() => new VirgilStreamCipher(invalidPublicKey),
				TypeError
			);
		});

		it ('pass signature to constructor', () => {
			const keyPair = createVirgilKeyPair();
			const streamCipher = new VirgilStreamCipher(keyPair.publicKey, 'any');

			streamCipher.start();
			streamCipher.update('test', 'utf8');
			streamCipher.final();
		})
	});

	describe('prerequisites', () => {
		let streamCipher: VirgilStreamCipher;

		beforeEach(() => {
			const keyPair = createVirgilKeyPair();
			streamCipher = new VirgilStreamCipher(keyPair.publicKey);
		});

		it ('update cannot be called before start', () => {
			assert.throws(() => {
				streamCipher.update(Buffer.from('chunk'));
			}, 'prerequisite is broken');
		});

		it ('final cannot be called before start', () => {
			assert.throws(() => {
				streamCipher.final();
			}, 'prerequisite is broken');
		});

		it ('update cannot be called after final', () => {
			streamCipher.start();
			streamCipher.update('test', 'utf8');
			streamCipher.final();

			assert.throws(() => {
				streamCipher.update('test', 'utf8');
			}, 'Illegal state');
		});

		it ('start cannot be called after final', () => {
			streamCipher.start();
			streamCipher.update('test', 'utf8');
			streamCipher.final();

			assert.throws(() => {
				streamCipher.start();
			}, 'Illegal state');
		});


		it ('final cannot be called after final', () => {
			streamCipher.start();
			streamCipher.update('test', 'utf8');
			streamCipher.final();

			assert.throws(() => {
				streamCipher.final();
			}, 'Illegal state');
		});
	});

	if (process.browser) {
		describe('behavior in browser', () => {
			let streamCipher: VirgilStreamCipher;
			beforeEach(() => {
				const keyPair = createVirgilKeyPair();
				streamCipher = new VirgilStreamCipher(keyPair.publicKey);
			});

			it ('start throws if already disposed', () => {
				streamCipher.dispose();
				assert.throws(() => {
					streamCipher.start();
				}, 'Illegal state');
			});

			it ('update throws if already disposed', () => {
				streamCipher.dispose();
				assert.throws(() => {
					streamCipher.update(Buffer.from('chunk'));
				}, 'Illegal state');
			});

			it ('final throws if already disposed', () => {
				streamCipher.dispose();
				assert.throws(() => {
					streamCipher.final();
				}, 'Illegal state');
			});
		});
	}
});
