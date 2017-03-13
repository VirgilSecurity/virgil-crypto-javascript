import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Extracts public key out of private key
 *
 * @param {Buffer} privateKey - Private key to extract from
 * @param {Buffer} [privateKeyPassword] - Private key password, if required
 *
 * @returns {Buffer} - Extracted public key
 * */
export function extractPublicKey(privateKey, privateKeyPassword = new Buffer(0)) {
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = bufferToByteArray(privateKeyPassword);

	try {
		return convertToBufferAndRelease(
			VirgilCrypto.VirgilKeyPair.extractPublicKey(
				privateKeyArr, passwordArr
			));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		privateKeyArr.delete();
		passwordArr.delete();
	}
}
