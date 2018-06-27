import { cryptoWrapper } from '../node/wrapper';
import { KeyPair } from '../common';

describe ('encryption with detached content info', () => {
	describe('signTheEncryptDetached', () => {
		it ('returns encrypted data and content info separately', () => {
			const data = Buffer.from('message');
			const senderKeyPair = cryptoWrapper.generateKeyPair();
			const senderId = Buffer.from('sender_id');
			const recipientKeyPair = cryptoWrapper.generateKeyPair();
			const recipientId = Buffer.from('recipient_id');

			const { encryptedData, metadata } = cryptoWrapper.signThenEncryptDetached(
				data,
				{ key: senderKeyPair.privateKey, identifier: senderId },
				[ { key: recipientKeyPair.publicKey, identifier: recipientId } ]
			);

			assert.isTrue(Buffer.isBuffer(encryptedData));
			assert.isFalse(encryptedData.equals(data));
			assert.isTrue(Buffer.isBuffer(metadata));
		});
	});

	describe ('decryptThenVerifyDetached', () => {
		let data,
			senderKeyPair: KeyPair,
			senderId: Buffer,
			recipientKeyPair: KeyPair,
			recipientId: Buffer,
			encryptedData: Buffer,
			metadata: Buffer;

		before (() => {
			data = Buffer.from('message');
			senderKeyPair = cryptoWrapper.generateKeyPair();
			senderId = Buffer.from('sender_id');
			recipientKeyPair = cryptoWrapper.generateKeyPair();
			recipientId = Buffer.from('recipient_id');

			const result = cryptoWrapper.signThenEncryptDetached(
				data,
				{ key: senderKeyPair.privateKey, identifier: senderId },
				[ { key: recipientKeyPair.publicKey, identifier: recipientId } ]
			);

			encryptedData = result.encryptedData;
			metadata = result.metadata;
		});

		it ('can decrypt', () => {
			const decryptedData = cryptoWrapper.decryptThenVerifyDetached(
				encryptedData,
				metadata,
				{ key: recipientKeyPair.privateKey, identifier: recipientId },
				[ { key: senderKeyPair.publicKey, identifier: senderId } ]
			);

			assert.equal(decryptedData.toString(), 'message');
		});

		it ('throws when given a wrong private key', () => {
			const wrongKeyPair = cryptoWrapper.generateKeyPair();
			const wrongId = Buffer.from('wrong');
			assert.throws(() => {
				cryptoWrapper.decryptThenVerifyDetached(
					encryptedData,
					metadata,
					{ key: wrongKeyPair.privateKey, identifier: wrongId },
					[ { key: senderKeyPair.publicKey, identifier: senderId } ]
				);
			}, /wrong private key/i);
		});

		it ('throws when given a wrong public key', () => {
			const wrongKeyPair = cryptoWrapper.generateKeyPair();
			const wrongId = Buffer.from('wrong');
			assert.throws(() => {
				cryptoWrapper.decryptThenVerifyDetached(
					encryptedData,
					metadata,
					{ key: recipientKeyPair.privateKey, identifier: recipientId },
					[ { key: wrongKeyPair.publicKey, identifier: wrongId } ]
				);
			}, /wrong public key/i);
		});

		it ('throws when signature is invalid for key', () => {
			const wrongKeyPair = cryptoWrapper.generateKeyPair();
			assert.throws(() => {
				cryptoWrapper.decryptThenVerifyDetached(
					encryptedData,
					metadata,
					{ key: recipientKeyPair.privateKey, identifier: recipientId },
					[ { key: wrongKeyPair.publicKey, identifier: senderId } ] // wrong key, correct id
				);
			}, /signature verification has failed/i);
		});
	});

	describe('decryptThenVerifyDetached with multiple recipients', () => {
		let data: Buffer,
			senderKeyPair: KeyPair,
			senderId: Buffer,
			recipients: Array<{ keyPair: KeyPair, id: Buffer }> = [],
			encryptedData: Buffer,
			metadata: Buffer;

		const recipientCount = 3;

		before (() => {
			data = Buffer.from('message');
			senderKeyPair = cryptoWrapper.generateKeyPair();
			senderId = Buffer.from('sender_id');
			for (let i = 0; i < recipientCount; i++) {
				recipients.push({
					keyPair: cryptoWrapper.generateKeyPair(),
					id: Buffer.from('recipient_' + i)
				});
			}

			const result = cryptoWrapper.signThenEncryptDetached(
				data,
				{ key: senderKeyPair.privateKey, identifier: senderId },
				recipients.map(r => ({ key: r.keyPair.publicKey, identifier: r.id }))
			);
			encryptedData = result.encryptedData;
			metadata = result.metadata;
		});

		it ('can decrypt with any of the recipient keys', () => {
			for (let i = 0; i < recipientCount; i++) {
				const decryptedData = cryptoWrapper.decryptThenVerifyDetached(
					encryptedData,
					metadata,
					{ key: recipients[i].keyPair.privateKey, identifier: recipients[i].id },
					[ { key: senderKeyPair.publicKey, identifier: senderId } ]
				);

				assert.equal(decryptedData.toString(), 'message');
			}
		});
	});
});
