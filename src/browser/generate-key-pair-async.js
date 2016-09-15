import browser from 'bowser';
import KeysTypesEnum from '../lib/keys-types-enum';
import CryptoWorkerApi from './crypto-worker-api';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';
import { generateKeyPair } from './generate-key-pair';

/**
 * Asynchronously generate the key pair - public and private keys.
 *
 * @param {Object} [options={}] - Keys options.
 * @param {string=} options.password - Private key password (Optional).
 * @param {string=} options.type - Keys type identifier (Optional). If provided must be one of KeysTypesEnum values.
 * @returns {Promise<{publicKey: *, privateKey: *}>}
 */
export function generateKeyPairAsync (options = {}) {
	const password = options.password || '';
	let keysType = options.type;

	if (keysType && !KeysTypesEnum.hasOwnProperty(keysType)) {
		throwValidationError('00003', {
			arg: 'keysType',
			text: `must be one of ${_.values(KeysTypesEnum).join(', ')} - use the KeysTypesEnum to get it.`
		});
	}

	if (!_.isString(password)) {
		throwValidationError('00001', { arg: 'password', type: 'String' });
	}

	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(generateKeyPair({ password, type: KeysTypesEnum[keysType] }));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi.generateKeyPair(password, KeysTypesEnum[keysType])
			.catch(() => throwVirgilError('90007', { password: password }));
	}
}

export default generateKeyPairAsync;
