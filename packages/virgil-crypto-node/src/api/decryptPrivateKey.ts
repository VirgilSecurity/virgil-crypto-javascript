import { assert, errorFromNativeError } from 'virgil-crypto-utils';
import lib from '../../virgil_crypto_node.node';
import { isBuffer, wrapFunction } from '../utils';

const decryptPrivateKeyFn = wrapFunction(lib.VirgilKeyPair.decryptPrivateKey, lib.VirgilKeyPair);

/**
 * Decrypts encrypted private key.
 * @param {Buffer} privateKey - Private key to decrypt.
 * @param {Buffer} [password] - Private key password.
 *
 * @returns {Buffer} - Decrypted private key
 * */
export function decryptPrivateKey(privateKey: Buffer, password: Buffer) {
	assert(isBuffer(privateKey), 'Cannot decrypt private key. `privateKey` must be a Buffer');
	assert(isBuffer(password), 'Cannot decrypt private key. `password` must be a Buffer');

	try {
		return decryptPrivateKeyFn(privateKey, password);
	} catch (e) {
		throw errorFromNativeError(e);
	}
}
