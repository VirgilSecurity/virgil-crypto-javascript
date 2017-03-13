import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Converts PEM formatted private key to DER format.
 * @param {Buffer} privateKey - Private key in PEM format
 * @param {Buffer} [privateKeyPassword] - Private key password, if encrypted.
 * @returns {Buffer}
 * */
export function privateKeyToDER(
	privateKey, privateKeyPassword = new Buffer(0)) {

	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword);

	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = bufferToByteArray(privateKeyPassword);
	try {
		return convertToBufferAndRelease(
			VirgilCrypto.VirgilKeyPair.privateKeyToDER(
				privateKeyArr, passwordArr
			));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		privateKeyArr.delete();
		passwordArr.delete();
	}
}
