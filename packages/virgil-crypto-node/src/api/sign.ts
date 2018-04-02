import { errorFromNativeError } from 'virgil-crypto-utils';
import lib from '../../virgil_crypto_node.node';
import { wrapFunction } from '../utils';

/**
 * Calculates the digital signature of the given data using the given private key.
 *
 * @param data {Buffer} - Data to sign.
 * @param privateKey {Buffer} - Private key to use.
 * @param [privateKeyPassword] {Buffer} - Optional password the private key is encrypted with.
 * @returns {Buffer} - Digital signature.
 */
export function sign (data: Buffer, privateKey: Buffer, privateKeyPassword = new Buffer(0)) {
	const signer = new lib.VirgilSigner();
	const signFn = wrapFunction(signer.sign, signer);

	try {
		return signFn(data, privateKey, privateKeyPassword);
	} catch (e) {
		throw errorFromNativeError(e);
	}
}
