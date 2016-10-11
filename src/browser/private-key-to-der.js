import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Converts PEM formatted private key to DER format.
 * @param {Buffer} privateKey - Private key in PEM format
 * @param {Buffer} [privateKeyPassword] - Private key password, if encrypted.
 * @returns {Buffer}
 * */
export function privateKeyToDER(privateKey, privateKeyPassword = new Buffer(0)) {
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(privateKeyPassword);

	return byteArrayToBuffer(
		VirgilCrypto.VirgilKeyPair.privateKeyToDER(
			bufferToByteArray(privateKey),
			bufferToByteArray(privateKeyPassword)));
}
