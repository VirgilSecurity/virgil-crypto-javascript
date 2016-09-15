import _ from 'lodash';
import VirgilCrypto from './utils/crypto-module';
import * as CryptoUtils from './utils/crypto-utils';
import KeysTypesEnum from '../lib/keys-types-enum';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';

/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keys options.
 * @param {string=} options.password - Private key password (Optional).
 * @param {string=} options.type - Keys type identifier (Optional). If provided must be one of KeysTypesEnum values.
 * @returns {{publicKey: *, privateKey: *}}
 */
export function generateKeyPair (options = {}) {
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

	const KeyPair = VirgilCrypto.VirgilKeyPair;

	const generate = keysType ?
		KeyPair.generate.bind(KeyPair, KeyPair.Type[KeysTypesEnum[keysType]]) :
		KeyPair.generateRecommended.bind(KeyPair);

	let publicKey;
	let privateKey;

	try {
		const passwordByteArray = CryptoUtils.toByteArray(password);
		const virgilKeys = generate(passwordByteArray);

		publicKey = virgilKeys.publicKey().toUTF8();
		privateKey = virgilKeys.privateKey().toUTF8();

		// cleanup memory to avoid memory leaks
		passwordByteArray.delete();
		virgilKeys.delete();
	} catch (e) {
		throwVirgilError('90007', { password: password });
	}

	return { publicKey, privateKey };
}

export default generateKeyPair;
