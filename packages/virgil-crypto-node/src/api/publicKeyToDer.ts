import { assert, errorFromNativeError } from 'virgil-crypto-utils';
import lib from '../../virgil_crypto_node.node';
import { wrapFunction, isBuffer } from '../utils';

const toDer = wrapFunction(lib.VirgilKeyPair.publicKeyToDER, lib.VirgilKeyPair);

/**
 * Converts PEM formatted public key to DER format.
 * @param {Buffer} publicKey - Public key in PEM format
 * @returns {Buffer} Public key in DER fromat.
 * */
export function publicKeyToDer(publicKey: Buffer) {
	assert(isBuffer(publicKey), 'Cannot convert private key to DER. Argument "publicKey" must be a Buffer');

	try {
		return toDer(publicKey);
	} catch (e) {
		throw errorFromNativeError(e);
	}
}
