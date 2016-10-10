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
	let isVerified;

	try {
		isVerified = virgilSigner.verify(
			bufferToByteArray(data),
			bufferToByteArray(sign),
			bufferToByteArray(publicKey));
	} catch (e) {
		throwVirgilError('90006', { error: e.message });
	} finally {
		virgilSigner.delete();
	}

	return isVerified;
}

export default verify;
