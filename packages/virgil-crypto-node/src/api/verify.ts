import { errorFromNativeError } from 'virgil-crypto-utils';
import lib from '../../virgil_crypto_node.node';
import { wrapFunction } from '../utils';

/**
 * Verifies digital signature of the given data for the given public key.
 *
 * @param data {Buffer} - Data to verify.
 * @param signature {Buffer} - The signature.
 * @param publicKey {Buffer} - The public key.
 *
 * @returns {boolean} - True if signature is valid for the given public key and data,
 * otherwise False.
 */
export function verify (data: Buffer, signature: Buffer, publicKey: Buffer) {
	const signer = new lib.VirgilSigner();
	const verifyFn = wrapFunction(signer.verify, signer);

	try {
		return verifyFn(data, signature, publicKey);
	} catch (e) {
		throw errorFromNativeError(e);
	}
}
