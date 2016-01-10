import _ from 'lodash';
export { Buffer } from 'buffer';
import VirgilCrypto from './utils/crypto-module';
import * as CryptoUtils from './utils/crypto-utils';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';

/**
 * Verify signed data using public key
 *
 * @param data {string|Buffer}
 * @param publicKey {string}
 * @param sign {Buffer}
 * @returns {boolean}
 */
export function verify (data, publicKey, sign) {
	if (!(_.isString(data) || Buffer.isBuffer(data))) {
		throwValidationError('00001', { arg: 'data', type: 'String or Buffer' });
	}

	if (!_.isString(publicKey)) {
		throwValidationError('00001', { arg: 'publicKey', type: 'String' });
	}

	let virgilSigner = new VirgilCrypto.VirgilSigner();
	let isVerified;

	try {
		let dataByteArray = CryptoUtils.toByteArray(data);
		let publicKeyByteArray = CryptoUtils.toByteArray(publicKey);
		let signByteArray = CryptoUtils.toByteArray(sign);
		isVerified = virgilSigner.verify(dataByteArray, signByteArray, publicKeyByteArray);

		// cleanup memory to avoid memory leaks
		dataByteArray.delete();
		publicKeyByteArray.delete();
		signByteArray.delete();
	} catch (e) {
		throwVirgilError('90006', { initialData: data, key: publicKey, sign: sign });
	} finally {
		virgilSigner.delete();
	}

	return isVerified;
}

export default verify;
