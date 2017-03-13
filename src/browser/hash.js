import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Produces a hash of given data
 *
 * @param {Buffer} data - Data to hash
 * @param {string} [algorithm] - Hash algorithm to use. Default is SHA256
 *
 * @returns {Buffer}
 * */
export function hash(data, algorithm) {
	checkIsBuffer(data, 'data');
	algorithm = algorithm || VirgilCrypto.VirgilHashAlgorithm.SHA256;
	const dataArr = bufferToByteArray(data);
	const virgilHash = new VirgilCrypto.VirgilHash(algorithm);

	try {
		const hash = virgilHash.hash(dataArr);
		return convertToBufferAndRelease(hash);
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		virgilHash.delete();
		dataArr.delete();
	}
}
