import browser from 'bowser';
import KeyPairType from '../lib/key-pair-type';
import CryptoWorkerApi from './crypto-worker-api';
import { throwVirgilError, throwValidationError, checkIsBuffer } from './utils/crypto-errors';
import { toBase64 } from './utils/crypto-utils';
import { generateKeyPair } from './generate-key-pair';

/**
 * Asynchronously generate the key pair - public and private keys.
 *
 * @param {Object} [options={}] - Keys options.
 * @param {Buffer=} options.password - Private key password (Optional).
 * @param {string=} options.type - Keys type identifier (Optional). If provided must be one of KeyPairType values.
 * @returns {Promise<{publicKey: Buffer, privateKey: Buffer}>}
 */
export function generateKeyPairAsync (options = {}) {
	let { type, password } = options;

	if (type && !KeyPairType.hasOwnProperty(type)) {
		throwValidationError('00002', {
			arg: 'type',
			type: `one of ${_.values(KeyPairType).join(', ')} - use the KeyPairType to get it.`
		});
	}

	if (password) {
		checkIsBuffer(password);
	} else {
		password = new Buffer(0);
	}


	if (browser.msie || browser.msedge) {
		return new Promise((resolve, reject) => {
			try {
				resolve(generateKeyPair({ password, type: KeyPairType[type] }));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		return CryptoWorkerApi.generateKeyPair(toBase64(password), KeyPairType[type])
			.then(({ privateKey, publicKey }) => {
				return {
					privateKey: new Buffer(privateKey, 'utf8'),
					publicKey: new Buffer(publicKey, 'utf8')
				};
			})
			.catch((e) => throwVirgilError('90007', { error: e }));
	}
}

export default generateKeyPairAsync;
