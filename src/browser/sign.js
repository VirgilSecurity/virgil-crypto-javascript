import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
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
	let sign;

	try {
		sign = byteArrayToBuffer(
			virgilSigner.sign(
				bufferToByteArray(data),
				bufferToByteArray(privateKey),
				bufferToByteArray(privateKeyPassword)));

	} catch (e) {
		throwVirgilError('90005', { error: e.message });
	} finally {
		virgilSigner.delete();
	}

	return sign;
}

export default sign;
