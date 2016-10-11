import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { checkIsBuffer } from './utils/crypto-errors';

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

	iterations = iterations || 2048;
	algorithm = algorithm || VirgilCrypto.VirgilHashAlgorithm.SHA384;
	const  pbkdf = new VirgilCrypto.VirgilPBKDF(bufferToByteArray(salt), iterations);
	pbkdf.setHashAlgorithm(algorithm);

	return byteArrayToBuffer(pbkdf.derive(bufferToByteArray(value), 0));
}
