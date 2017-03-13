import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Sign the encrypted data using private key
 *
 * @param data {Buffer}
 * @param privateKey {Buffer}
 * @param [privateKeyPassword] {Buffer}
 * @returns {Buffer}
 */
export function sign (data, privateKey, privateKeyPassword = new Buffer(0)) {
	checkIsBuffer(data, 'data');
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	const virgilSigner = new VirgilCrypto.VirgilSigner();
	const dataArr = bufferToByteArray(data);
	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = bufferToByteArray(privateKeyPassword);

	try {
		return convertToBufferAndRelease(
			virgilSigner.sign(dataArr, privateKeyArr, passwordArr)
		);
	} catch (e) {
		throwVirgilError('90005', { error: e.message });
	} finally {
		virgilSigner.delete();
		dataArr.delete();
		privateKeyArr.delete();
		passwordArr.delete();
	}
}

export default sign;
