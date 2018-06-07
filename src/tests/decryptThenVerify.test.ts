import { cryptoWrapper } from '../node/wrapper';

describe('signThenEncrypt -> decryptThenVerify with multiple keys', function () {

	it('should decrypt and verify data successfully given right keys', function () {
		const plainData = Buffer.from('Secret message');

		const senderKeyPair = cryptoWrapper.generateKeyPair();
		const senderIdentifier = Buffer.from('SENDER');

		const recipientKeyPair = cryptoWrapper.generateKeyPair();
		const recipientIdentifier = Buffer.from('RECIPIENT');

		const additionalKeyPair = cryptoWrapper.generateKeyPair();
		const additionalIdentifier = Buffer.from('Additional');

		const anotherKeyPair = cryptoWrapper.generateKeyPair();
		const anotherIdentifier = Buffer.from('Another');

		const encryptedData = cryptoWrapper.signThenEncrypt(
			plainData,
			{
				key: senderKeyPair.privateKey,
				identifier: senderIdentifier
			}, {
				identifier: recipientIdentifier,
				key: recipientKeyPair.publicKey
			}
		);

		const decryptedData = cryptoWrapper.decryptThenVerify(
			encryptedData,
			{
				identifier: recipientIdentifier,
				key: recipientKeyPair.privateKey
			},
			[
				{
					key: additionalKeyPair.publicKey,
					identifier: additionalIdentifier
				},
				{
					key: anotherKeyPair.publicKey,
					identifier: anotherIdentifier
				},
				{
					key: senderKeyPair.publicKey,
					identifier: senderIdentifier
				}
			]
		);

		assert.isTrue(decryptedData.equals(plainData), 'data decrypted successfully');
	});

	it('should fail verification given the wrong public key', function () {
		const plainData = Buffer.from('Secret message');

		const senderKeyPair = cryptoWrapper.generateKeyPair();
		const senderIdentifier = Buffer.from('SENDER');

		const recipientKeyPair = cryptoWrapper.generateKeyPair();
		const recipientIdentifier = Buffer.from('RECIPIENT');

		const additionalKeyPair = cryptoWrapper.generateKeyPair();
		const additionalIdentifier = Buffer.from('Additional');

		const anotherKeyPair = cryptoWrapper.generateKeyPair();
		const anotherIdentifier = Buffer.from('Another');


		const encryptedData = cryptoWrapper.signThenEncrypt(
			plainData,
			{
				key: senderKeyPair.privateKey,
				identifier: senderIdentifier
			},
			{
				identifier: recipientIdentifier,
				key: recipientKeyPair.publicKey
			}
		);

		assert.throws(function() {
			cryptoWrapper.decryptThenVerify(
				encryptedData,
				{
					identifier: recipientIdentifier,
					key: recipientKeyPair.privateKey
				},
				[
					{
						key: additionalKeyPair.publicKey,
						identifier: additionalIdentifier
					},
					{
						key: anotherKeyPair.publicKey,
						identifier: anotherIdentifier
					}
				]
			);
		},/Signature verification has failed/, 'throws when signature is invalid');
	});

	it('should decrypt and verify without signer id in metadata', function () {
		const plainData = Buffer.from('Secret message');

		const senderKeyPair = cryptoWrapper.generateKeyPair();
		const senderIdentifier = Buffer.from('SENDER');

		const recipientKeyPair = cryptoWrapper.generateKeyPair();
		const recipientIdentifier = Buffer.from('RECIPIENT');

		const additionalKeyPair = cryptoWrapper.generateKeyPair();
		const additionalIdentifier = Buffer.from('Additional');

		const anotherKeyPair = cryptoWrapper.generateKeyPair();
		const anotherIdentifier = Buffer.from('Another');

		const encryptedData = cryptoWrapper.signThenEncrypt(
			plainData,
			{
				key: senderKeyPair.privateKey // no signer id is passed
			},
			{
				identifier: recipientIdentifier,
				key: recipientKeyPair.publicKey
			}
		);

		const decryptedData = cryptoWrapper.decryptThenVerify(
			encryptedData,
			{
				identifier: recipientIdentifier,
				key: recipientKeyPair.privateKey
			},
			[{
					key: additionalKeyPair.publicKey,
					identifier: additionalIdentifier
				}, {
					key: anotherKeyPair.publicKey,
					identifier: anotherIdentifier
				}, {
					key: senderKeyPair.publicKey,
					identifier: senderIdentifier
				}
			]
		);

		assert.isTrue(decryptedData.equals(plainData), 'data decrypted successfully');
	});
});
