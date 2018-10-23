import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilStreamDecipher } from '../../streams/VirgilStreamDecipher';
import { VirgilPrivateKey } from '../../VirgilPrivateKey';

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

	describe('prerequisites', () => {
		let streamDecipher: VirgilStreamDecipher;
		let ciphertext: Buffer;

		beforeEach(() => {
			const keyPair = cryptoWrapper.generateKeyPair();
			const keyPairId = Buffer.from('key_pair_id');

			streamDecipher = new VirgilStreamDecipher(
				new VirgilPrivateKey(keyPairId, keyPair.privateKey)
			);

			ciphertext = cryptoWrapper.encrypt(Buffer.from('test'), { identifier: keyPairId, key: keyPair.publicKey });
		});

		it ('update cannot be called after final', () => {
			streamDecipher.update(ciphertext);
			streamDecipher.final();

			assert.throws(() => {
				streamDecipher.update(ciphertext);
			}, 'Illegal state');
		});

		it ('final cannot be called after final', () => {
			streamDecipher.update(ciphertext);
			streamDecipher.final();

			assert.throws(() => {
				streamDecipher.final();
			}, 'Illegal state');
		});
	});

	if (process.browser) {
		describe('behavior in browser', () => {
			let streamDecipher: VirgilStreamDecipher;
			let ciphertext: Buffer;
			beforeEach(() => {
				const keyPair = cryptoWrapper.generateKeyPair();
				const keyPairId = Buffer.from('key_pair_id');

				streamDecipher = new VirgilStreamDecipher(
					new VirgilPrivateKey(keyPairId, keyPair.privateKey)
				);

				ciphertext = cryptoWrapper.encrypt(Buffer.from('test'), { identifier: keyPairId, key: keyPair.publicKey });
			});

			it ('update throws if already disposed', () => {
				streamDecipher.dispose();
				assert.throws(() => {
					streamDecipher.update(ciphertext);
				}, 'Illegal state');
			});

			it ('final throws if already disposed', () => {
				streamDecipher.dispose();
				assert.throws(() => {
					streamDecipher.final();
				}, 'Illegal state');
			});
		});
	}
});
