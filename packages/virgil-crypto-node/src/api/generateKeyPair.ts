import { VirgilCryptoError, KeyPairType, errorFromNativeError } from 'virgil-crypto-utils';
import lib from '../../virgil_crypto_node.node';
import { wrapFunction, isBuffer, virgilByteArrayToBuffer } from '../utils';

const generate = wrapFunction(lib.VirgilKeyPair.generate, lib.VirgilKeyPair);
const generateRecommended = wrapFunction(lib.VirgilKeyPair.generateRecommended, lib.VirgilKeyPair);

export type KeyPairOptions = {
	type?: KeyPairType,
	password?: Buffer
};

/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keypair options.
 * @param {Buffer} [options.password] - Private key password (Optional).
 * @param {string} [options.type=] - Keys type identifier (Optional).
 * 		If provided must be one of KeyPairType values.
 * @returns {{publicKey: Buffer, privateKey: Buffer}}
 */
export function generateKeyPair (options: KeyPairOptions = {}) {
	let { type, password = new Buffer(0) } = options;


	if (type && Object.keys(KeyPairType).indexOf(type) === -1) {
		throw new VirgilCryptoError(
			'Cannot generate keypair. Parameter "type" is invalid'
		);
	}

	if (!isBuffer(password)) {
		throw new VirgilCryptoError(
			'Cannot generate keypair. Parameter "password" must be a Buffer'
		);
	}

	let keypair;
	try {
		if (type) {
			keypair = generate(lib.VirgilKeyPair.Type[type], password)
		} else {
			keypair = generateRecommended(password);
		}
	} catch (e) {
		throw errorFromNativeError(e);
	}

	return {
		privateKey: virgilByteArrayToBuffer(keypair.privateKey()),
		publicKey: virgilByteArrayToBuffer(keypair.publicKey())
	};
}
