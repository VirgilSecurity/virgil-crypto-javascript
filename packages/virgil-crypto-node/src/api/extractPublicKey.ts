import { assert, errorFromNativeError } from 'virgil-crypto-utils';
import lib from '../../virgil_crypto_node.node';
import { isBuffer, wrapFunction } from '../utils';

const extractPublicKeyFn = wrapFunction(lib.VirgilKeyPair.extractPublicKey, lib.VirgilKeyPair);

/**
 * Extracts public key out of private key.
 *
 * @param {Buffer} privateKey - Private key to extract from.
 * @param {Buffer} [password] - Private key password if private key is encrypted.
 *
 * @returns {Buffer} - Extracted public key
 * */
export function extractPublicKey(privateKey: Buffer, password: Buffer = new Buffer(0)) {
	assert(isBuffer(privateKey), 'Cannot extract public key. `privateKey` must be a Buffer');
	assert(isBuffer(password), 'Cannot extract public key. `password` must be a Buffer');

	try {
		return extractPublicKeyFn(privateKey, password);
	} catch (e) {
		throw errorFromNativeError(e);
	}
}
