import VirgilCrypto from './utils/crypto-module';
import * as u from './utils/crypto-utils';

export function extractPublicKey(privateKey, privateKeyPassword = '') {
	const privateKeyByteArray = u.toByteArray(privateKey);
	const passwordByteArray = u.toByteArray(privateKeyPassword);

	const pubKeyByteArray = VirgilCrypto.VirgilKeyPair.extractPublicKey(privateKeyByteArray, passwordByteArray);
	return u.byteArrayToString(pubKeyByteArray);
}
