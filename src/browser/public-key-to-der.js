import isString from 'lodash/isString';
import VirgilCrypto from './utils/crypto-module';
import * as CryptoUtils from './utils/crypto-utils';
import { throwValidationError } from './utils/crypto-errors';

export function publicKeyToDER(publicKey) {
	if (!isString(publicKey) && !Buffer.isBuffer(publicKey)) {
		throwValidationError('00003', { arg: 'publicKey', text: 'must be a string or Buffer.'});
	}

	const publicKeyByteArray = CryptoUtils.toByteArray(publicKey);
	const derByteArray = VirgilCrypto.VirgilKeyPair.publicKeyToDER(publicKeyByteArray);
	return CryptoUtils.byteArrayToBuffer(derByteArray);
}
