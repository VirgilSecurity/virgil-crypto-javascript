import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Extracts public key out of private key
 *
 * @param {Buffer} privateKey - Private key to extract from
 * @param {Buffer} [privateKeyPassword] - Private key password, if required
 *
 * @returns {Buffer} - Extracted public key
 * */
export function extractPublicKey(privateKey, privateKeyPassword = new Buffer(0)) {
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	return byteArrayToBuffer(
		VirgilCrypto.VirgilKeyPair.extractPublicKey(
			bufferToByteArray(privateKey),
			bufferToByteArray(privateKeyPassword)));
}
