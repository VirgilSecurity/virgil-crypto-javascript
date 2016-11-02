import VirgilCrypto from './utils/crypto-module';
import { bufferToByteArray, byteArrayToBuffer, stringToByteArray } from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';
import * as constants from '../lib/constants';

/**
 * Decrypts the given data with private key and verifies the signature with public key
 *
 * @param {Buffer} cipherData - Data to decrypt
 * @param {Buffer} recipientId - Recipient ID used for encryption
 * @param {Buffer} privateKey - Private key
 * @param {Buffer} publicKey - Public key to validate the signature with
 *
 * @returns {Buffer} Decrypted data
 * */
export function decryptThenVerify (cipherData, recipientId, privateKey, publicKey) {
	checkIsBuffer(cipherData, 'cipherData');
	checkIsBuffer(recipientId, 'recipientId');
	checkIsBuffer(privateKey, 'privateKey');
	checkIsBuffer(publicKey, 'publicKey');

	var signer = new VirgilCrypto.VirgilSigner();
	var cipher = new VirgilCrypto.VirgilCipher();
	var plainData;
	var isValid;

	try {
		plainData = cipher.decryptWithKey(
			bufferToByteArray(cipherData),
			bufferToByteArray(recipientId),
			bufferToByteArray(privateKey),
			stringToByteArray(''));

		let signature = cipher
			.customParams()
			.getData(stringToByteArray(constants.DATA_SIGNATURE_KEY));

		isValid = signer.verify(plainData, signature, bufferToByteArray(publicKey));
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		signer.delete();
		cipher.delete();
	}

	if (!isValid) {
		throwVirgilError('10000', { error: 'Signature verification has failed.'});
	}

	return byteArrayToBuffer(plainData);
}

export default decryptThenVerify;

