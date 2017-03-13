import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import KeyPairType from '../lib/key-pair-type';
import {
	throwVirgilError,
	throwValidationError,
	checkIsBuffer
} from './utils/crypto-errors';

/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keys options.
 * @param {Buffer} [options.password] - Private key password (Optional).
 * @param {string} [options.type=] - Keys type identifier (Optional).
 * 		If provided must be one of KeyPairType values.
 * @returns {{publicKey: Buffer, privateKey: Buffer}}
 */
export function generateKeyPair (options = {}) {
	let { type, password } = options;

	if (type && !Object.prototype.hasOwnProperty.call(KeyPairType, type)) {
		throwValidationError('00002', {
			arg: 'keysType',
			type: `one of ${Object.values(KeyPairType).join(', ')} - 
			use the KeyPairType to get it.`
		});
	}

	if (password) {
		checkIsBuffer(password, 'password');
	} else {
		password = new Buffer(0);
	}

	const KeyPair = VirgilCrypto.VirgilKeyPair;

	const generateKeyPair = type ?
		KeyPair.generate.bind(KeyPair, KeyPair.Type[KeyPairType[type]]) :
		KeyPair.generateRecommended;

	let publicKey;
	let privateKey;

	const passwordArr = bufferToByteArray(password);
	try {
		const keyPair = generateKeyPair(passwordArr);

		publicKey = convertToBufferAndRelease(keyPair.publicKey());
		privateKey = convertToBufferAndRelease(keyPair.privateKey());

		keyPair.delete();
	} catch (e) {
		throwVirgilError('90007', { error: e.message });
	} finally {
		passwordArr.delete();
	}

	return { publicKey, privateKey };
}

export default generateKeyPair;
