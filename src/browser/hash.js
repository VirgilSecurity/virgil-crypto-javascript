import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { checkIsBuffer } from './utils/crypto-errors';

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
	const virgilHash = new VirgilCrypto.VirgilHash(algorithm);
	const hash = virgilHash.hash(bufferToByteArray(data));
	return byteArrayToBuffer(hash);
}
