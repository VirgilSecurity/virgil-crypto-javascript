import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Converts PEM formatted public key to DER format.
 * @param {Buffer} publicKey - Public key in PEM format
 * @returns {Buffer}
 * */
export function publicKeyToDER(publicKey) {
	checkIsBuffer(publicKey, 'publicKey');
	const publicKeyArr = bufferToByteArray(publicKey);
	try {
		return convertToBufferAndRelease(
			VirgilCrypto.VirgilKeyPair.publicKeyToDER(publicKeyArr));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		publicKeyArr.delete();
	}
}
