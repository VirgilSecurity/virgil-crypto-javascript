import { assert, errorFromNativeError } from 'virgil-crypto-utils';
import lib from '../../virgil_crypto_node.node';
import { isBuffer, wrapFunction } from '../utils';

const encryptPrivateKeyFn = wrapFunction(lib.VirgilKeyPair.encryptPrivateKey, lib.VirgilKeyPair);

/**
 * Encrypts the private key with password
 *
 * @param {Buffer} privateKey - Private key to encrypt
 * @param {Buffer} password - Password to encrypt the private key with
 *
 * @returns {Buffer} - Encrypted private key
 * */
export function encryptPrivateKey(privateKey: Buffer, password: Buffer) {
	assert(isBuffer(privateKey), 'Cannot encrypt private key. `privateKey` must be a Buffer');
	assert(isBuffer(password), 'Cannot encrypt private key. `password` must be a Buffer');

	try {
		return encryptPrivateKeyFn(privateKey, password);
	} catch (e) {
		throw errorFromNativeError(e);
	}
}
