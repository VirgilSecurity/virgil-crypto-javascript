import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease,
	stringToByteArray
} from './utils/crypto-utils';
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

	const signer = new VirgilCrypto.VirgilSigner();
	const cipher = new VirgilCrypto.VirgilCipher();

	const cipherDataArr = bufferToByteArray(cipherData);
	const recipientIdArr = bufferToByteArray(recipientId);
	const privateKeyArr = bufferToByteArray(privateKey);
	const passwordArr = stringToByteArray('');
	const publicKeyArr = bufferToByteArray(publicKey);
	const signatureKeyArr = stringToByteArray(constants.DATA_SIGNATURE_KEY);

	let plainData, isValid;

	try {
		plainData = cipher.decryptWithKey(
			cipherDataArr,
			recipientIdArr,
			privateKeyArr,
			passwordArr);

		let signature = cipher
			.customParams()
			.getData(signatureKeyArr);

		isValid = signer.verify(plainData, signature, publicKeyArr);
	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		signer.delete();
		cipher.delete();
		cipherDataArr.delete();
		recipientIdArr.delete();
		privateKeyArr.delete();
		passwordArr.delete();
		publicKeyArr.delete();
		signatureKeyArr.delete();
	}

	if (!isValid) {
		throwVirgilError('10000', { error: 'Signature verification has failed.'});
	}

	return convertToBufferAndRelease(plainData);
}

export default decryptThenVerify;

