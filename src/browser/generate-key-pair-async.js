import browser from 'bowser';
import * as CryptoUtils from './utils/crypto-utils';
import KeysTypesEnum from '../lib/keys-types-enum';
import { createWorkerCryptoFunc } from './utils/create-worker-crypto-func';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';
import { generateKeyPair } from './generate-key-pair';

/**
 * Generate the key pair - public and private keys using workers
 *
 * @param [password = ''] {string}
 * @param [keysType = 'ecBrainpool512'] {string}
 * @returns {Promise}
 */
export function generateKeyPairAsync (password, keysType) {
	switch (arguments.length) {
		case 1:
			password = arguments[0];
			keysType = KeysTypesEnum.ecBrainpool512;
			break;

		case 2:
			password = arguments[0];
			keysType = KeysTypesEnum(arguments[1]);
			break;

		case 0:
		default:
			password = '';
			keysType = KeysTypesEnum.ecBrainpool512;
			break;
	}

	if (!_.isString(password)) {
		throwValidationError('00001', { arg: 'password', type: 'String' });
	}

	if (_.isUndefined(keysType)) {
		throwValidationError('00002', { arg: 'keysType', type: `equal to one of ${_.values(KeysTypesEnum).join(', ')} - use the KeysTypesEnum for it.` });
	}

	if (browser.msie) {
		return new Promise((resolve, reject) => {
			try {
				resolve(generateKeyPair(password, keysType));
			} catch (e) {
				reject(e.message);
			}
		});
	} else {
		let worker = createWorkerCryptoFunc(generateKeyPairAsyncWorker);

		return worker(password, keysType).catch(() => throwVirgilError('90007', { password: password }));
	}
}

function generateKeyPairAsyncWorker (password, keysType) {
	let deferred = this.deferred();

	try {
		let passwordByteArray = VirgilCryptoWorkerContext.VirgilByteArray.fromUTF8(password);
		let virgilKeys = VirgilCryptoWorkerContext.VirgilKeyPair[keysType](passwordByteArray);

		let publicKey = virgilKeys.publicKey().toUTF8();
		let privateKey = virgilKeys.privateKey().toUTF8(virgilKeys);

		// cleanup memory to avoid memory leaks
		passwordByteArray.delete();
		virgilKeys.delete();

		deferred.resolve({ publicKey: publicKey, privateKey: privateKey });
	} catch (e) {
		deferred.reject(e);
	}
}

export default generateKeyPairAsync;
