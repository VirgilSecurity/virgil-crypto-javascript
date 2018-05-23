import { cryptoApi } from '../node/api';

describe('signThenEncrypt -> decryptThenVerify', function () {

	it('should decrypt and verify data successfully given right keys', function () {
		const keyPair = cryptoApi.generateKeyPair();
		const identifier = Buffer.from('keypair_identifier');
		const plainData = Buffer.from('Secret message');
		const encryptedData = cryptoApi.signThenEncrypt(
			plainData,
			{
				key: keyPair.privateKey
			},
			{
				identifier,
				key: keyPair.publicKey
			}
		);

		const decryptedData = cryptoApi.decryptThenVerify(
			encryptedData,
			{
				identifier,
				key: keyPair.privateKey
			}, {
				key: keyPair.publicKey
			}
		);

		assert.isTrue(decryptedData.equals(plainData));
	});

	it('should fail verification given the wrong public key', function () {
		const keyPair = cryptoApi.generateKeyPair();
		const identifier = Buffer.from('keypair_identifier');
		const plainData = Buffer.from('Secret message');
		const encryptedData = cryptoApi.signThenEncrypt(
			plainData,
			{
				key: keyPair.privateKey
			}, {
				identifier,
				key: keyPair.publicKey
			}
		);

		const wrongPubkey = cryptoApi.generateKeyPair().publicKey;

		assert.throws(function() {
			cryptoApi.decryptThenVerify(
				encryptedData,
				{
					identifier,
					key: keyPair.privateKey
				}, {
					key: wrongPubkey
				}
			);
		},/Signature verification has failed/);
	});

	it('should sign with password-protected key', function () {
		const password = Buffer.from('pa$$w0rd');
		const keyPair = cryptoApi.generateKeyPair({ password: password });
		const identifier = Buffer.from('keypair_identifier');
		const plainData = Buffer.from('Secret message');
		const encryptedData = cryptoApi.signThenEncrypt(
			plainData,
			{
				key: keyPair.privateKey,
				password: password
			},
			{
				identifier: identifier,
				key: keyPair.publicKey
			}
		);

		const decryptedData = cryptoApi.decryptThenVerify(
			encryptedData,
			{
				identifier: identifier,
				key: keyPair.privateKey,
				password: password
			},
			{
				key: keyPair.publicKey
			});

		assert.isTrue(decryptedData.equals(plainData));
	});
});
