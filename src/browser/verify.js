import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';

/**
 * Verify signed data using public key
 *
 * @param data {Buffer}
 * @param sign {Buffer}
 * @param publicKey {Buffer}
 * @returns {boolean}
 */
export function verify (data, sign, publicKey) {
	checkIsBuffer(data, 'data');
	checkIsBuffer(publicKey, 'publicKey');
	checkIsBuffer(sign, 'sign');

	const virgilSigner = new VirgilCrypto.VirgilSigner();
	const dataArr = bufferToByteArray(data);
	const signArr = bufferToByteArray(sign);
	const publicKeyArr = bufferToByteArray(publicKey);

	try {
		return virgilSigner.verify(dataArr, signArr, publicKeyArr);
	} catch (e) {
		throwVirgilError('90006', { error: e.message });
	} finally {
		virgilSigner.delete();
		dataArr.delete();
		signArr.delete();
		publicKeyArr.delete();
	}
}

export default verify;
