import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError} from './utils/crypto-errors';

/**
 * Obfuscates data
 *
 * @param {Buffer} value - Value to be obfuscated
 * @param {Buffer} salt - The salt
 * @param {string} [algorithm] - Hash algorithm. Default is SHA384
 * @param {number} [iterations] - Number of iterations. Default is 2048.
 *
 * @returns {Buffer} - Obfuscated value
 * */
export function obfuscate (value, salt, algorithm, iterations) {
	checkIsBuffer(value, 'value');
	checkIsBuffer(salt, 'salt');

	const valueArr = bufferToByteArray(value);
	const saltArr = bufferToByteArray(salt);

	iterations = iterations || 2048;
	algorithm = algorithm || VirgilCrypto.VirgilHashAlgorithm.SHA384;

	try {
		const  pbkdf = new VirgilCrypto.VirgilPBKDF(saltArr, iterations);
		pbkdf.setHashAlgorithm(algorithm);
		return convertToBufferAndRelease(pbkdf.derive(valueArr, 0));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		valueArr.delete();
		saltArr.delete();
	}
}
