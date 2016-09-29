import isString from 'lodash/isString';
import VirgilCrypto from './utils/crypto-module';
import * as CryptoUtils from './utils/crypto-utils';
import { throwValidationError } from './utils/crypto-errors';

export function privateKeyToDER(privateKey, privateKeyPassword = '') {
	if (!isString(privateKey) && !Buffer.isBuffer(privateKey)) {
		throwValidationError('00003', { arg: 'privateKey s', text: 'must be a string or Buffer.'});
	}

	const privateKeyByteArray = CryptoUtils.toByteArray(privateKey);
	const passwordByteArray = CryptoUtils.toByteArray(privateKeyPassword);
	const derByteArray = VirgilCrypto.VirgilKeyPair.privateKeyToDER(privateKeyByteArray, passwordByteArray);
	return CryptoUtils.byteArrayToBuffer(derByteArray);
}
