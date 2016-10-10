import { VirgilCrypto, Buffer } from '../../../browser';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');
const INITIAL_DATA = Buffer.from('initial data', 'utf8');

describe('sign/verify', () => {

	it('should verify data signed with encrypted key', () => {
		let keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		let recipientId = Buffer.from('recipient_id', 'utf8');
		let encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, recipientId, keyPair.publicKey);
		let sign = VirgilCrypto.sign(encryptedData, keyPair.privateKey, PASSWORD);
		let verified = VirgilCrypto.verify(encryptedData, sign, keyPair.publicKey);

		expect(verified).toEqual(true);
	});

	it('should verify data signed with plain key', () => {
		let keyPair = VirgilCrypto.generateKeyPair();
		let encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, keyPair.publicKey, keyPair.publicKey);
		let sign = VirgilCrypto.sign(encryptedData, keyPair.privateKey);
		let verified = VirgilCrypto.verify(encryptedData, sign, keyPair.publicKey);

		expect(verified).toEqual(true);
	});
});
