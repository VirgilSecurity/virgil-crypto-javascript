import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer } from './utils/crypto-utils';
import { checkIsBuffer } from './utils/crypto-errors';

/**
 * Converts PEM formatted public key to DER format.
 * @param {Buffer} publicKey - Public key in PEM format
 * @returns {Buffer}
 * */
export function publicKeyToDER(publicKey) {
	checkIsBuffer(publicKey, 'publicKey');
	return byteArrayToBuffer(VirgilCrypto.VirgilKeyPair.publicKeyToDER(bufferToByteArray(publicKey)));
}
