import { VirgilCrypto, Buffer } from '../../../browser';

const PASSWORD = Buffer.from('veryStrongPa$$0rd', 'utf8');
const INITIAL_DATA = Buffer.from('initial data', 'utf8');

describe('signAsync/verifyAsync', () => {

	it('should verify data signed with encrypted key', async (cb) => {
		let keyPair = VirgilCrypto.generateKeyPair({ password: PASSWORD });
		let encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, keyPair.publicKey, keyPair.publicKey);
		let sign = await VirgilCrypto.signAsync(encryptedData, keyPair.privateKey, PASSWORD);
		let verified = await VirgilCrypto.verifyAsync(encryptedData, sign, keyPair.publicKey);

		expect(verified).toEqual(true);
		cb();
	});

	it('should verify data signed with plain key', async (cb) => {
		let keyPair = VirgilCrypto.generateKeyPair();
		let encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, keyPair.publicKey, keyPair.publicKey);
		let sign = await VirgilCrypto.signAsync(encryptedData, keyPair.privateKey);
		let verified = await VirgilCrypto.verifyAsync(encryptedData, sign, keyPair.publicKey);

		expect(verified).toEqual(true);
		cb();
	});

});
