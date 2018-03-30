import { VirgilCryptoError, errorFromNativeError } from 'virgil-crypto-utils';
import { lib } from '../asmjs';
import { wrapFunction, isBuffer } from '../utils';

const toDer = wrapFunction(lib.VirgilKeyPair.privateKeyToDER, lib.VirgilKeyPair);

/**
 * Converts PEM formatted private key to DER format.
 * @param {Buffer} privateKey - Private key in PEM format
 * @param {Buffer} [password] - Private key password, if encrypted.
 * @returns {Buffer} - Private key in DER format.
 * */
export function privateKeyToDer(privateKey: Buffer, password: Buffer = new Buffer(0)) {
	if (!isBuffer(privateKey)) {
		throw new VirgilCryptoError(
			'Cannot convert private key to DER. Argument "privateKey" must be a Buffer'
		);
	}

	if (!isBuffer(password)) {
		throw new VirgilCryptoError(
			'Cannot convert private key to DER. Argument "password" must be a Buffer'
		);
	}

	try {
		return toDer(privateKey, password);
	} catch (e) {
		throw errorFromNativeError(e);
	}

}
