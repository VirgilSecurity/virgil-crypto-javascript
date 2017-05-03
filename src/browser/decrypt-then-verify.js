import VirgilCrypto from './utils/crypto-module';
import {
	bufferToByteArray,
	convertToBufferAndRelease,
	stringToByteArray,
	byteArraysEqual
} from './utils/crypto-utils';
import { checkIsBuffer, throwVirgilError } from './utils/crypto-errors';
import { makePrivateKey } from './utils/makePrivateKey';
import { makePublicKey } from './utils/makePublicKey';
import * as constants from '../lib/constants';

export default decryptThenVerify;

/**
 * Decrypts the given data with private key and verify the signature with
 * public key.
 *
 * @param {Buffer} cipherData - Data to decrypt
 * @param {Buffer} recipientId - Recipient ID used for encryption
 * @param {Buffer|PrivateKeyInfo} privateKey - The `privateKey` can be an
 * 		object or a Buffer. If `privateKey` is a Buffer, it is treated as a
 * 		raw key without password. If it is an object, it is interpreted as a
 * 		hash containing two properties: `privateKey`, and `password`.
 * @param {Buffer|PublicKeyInfo[]} publicKey - Raw public key or an array of public
 * 		keys with identifiers to verify the signature with. If the cipher data
 * 		contains an identifier of the private key used to calculate the signature,
 * 		then the public key with that identifier from `publicKey` array will be
 * 		used to validate the signature, otherwise ANY one of the keys can validate
 * 		the signature. If the signature is not valid for ALL of the keys,
 * 		an exception is thrown.
 *
 * @returns {Buffer} Decrypted data
 * */
export function decryptThenVerify (cipherData, recipientId, privateKey, publicKey) {
	checkIsBuffer(cipherData, 'cipherData');
	checkIsBuffer(recipientId, 'recipientId');

	if (!publicKey || (Array.isArray(publicKey) && publicKey.length === 0)) {
		throwVirgilError('10000', {
			error: 'Cannot "decryptThenVerify". ' +
			'At least one verifier public key must be provided'
		});
	}

	const decryptingKey = makePrivateKey(privateKey, null, recipientId);
	const verifyingKeys = Array.isArray(publicKey) ?
		// don't pass `makePublicKey` function directly to `map`
		// because `map` passes an index as the second argument, which
		// might be interpreted as recipientId by `makePublicKey`
		publicKey.map(pubkey => makePublicKey(pubkey)) :
		[ makePublicKey(publicKey) ];

	const signer = new VirgilCrypto.VirgilSigner();
	const cipher = new VirgilCrypto.VirgilCipher();

	const cipherDataArr = bufferToByteArray(cipherData);
	const recipientIdArr = bufferToByteArray(recipientId);
	const signatureKeyArr = stringToByteArray(constants.DATA_SIGNATURE_KEY);
	const signerIdArr = stringToByteArray(constants.DATA_SIGNER_ID_KEY);

	let plainData, isValid, signerId;

	try {
		plainData = cipher.decryptWithKey(
			cipherDataArr,
			recipientIdArr,
			decryptingKey.privateKey,
			decryptingKey.password);

		const signature = cipher
			.customParams()
			.getData(signatureKeyArr);

		if (verifyingKeys.length === 1) {
			isValid = verifyWithSingleKey(signer, plainData, signature, verifyingKeys[0]);
		} else {
			signerId = tryGetSignerId(cipher);
			isValid = verifyWithMultipleKeys(signer, plainData, signature, verifyingKeys, signerId);
		}

	} catch (e) {
		throwVirgilError('10000', { error: e.message });
	} finally {
		signer.delete();
		cipher.delete();
		cipherDataArr.delete();
		recipientIdArr.delete();
		decryptingKey.delete();
		verifyingKeys.forEach(function (key) {
			key.delete();
		});
		signerId && signerId.delete();
		signatureKeyArr.delete();
		signerIdArr.delete();
	}

	if (!isValid) {
		throwVirgilError('10000', { error: 'Signature verification has failed.'});
	}

	return convertToBufferAndRelease(plainData);
}

function verifyWithSingleKey(signer, data, signature, key) {
	return signer.verify(data, signature, key.publicKey);
}

function verifyWithMultipleKeys(signer, data, signature, keys, signerId) {
	if (signerId) {
		// find the public key corresponding to signer id from metadata
		var signerPublicKey = keys.find(function (key) {
			return byteArraysEqual(signerId, key.recipientId);
		});

		return signerPublicKey ?
			signer.verify(data, signature, signerPublicKey.publicKey) :
			false;
	}

	// no signer id in metadata, try all public keys in sequence
	return keys.some(function (key) {
		return signer.verify(data, signature, key.publicKey);
	});
}

function tryGetSignerId(cipher) {
	var customParams = cipher.customParams();
	var key = stringToByteArray(constants.DATA_SIGNER_ID_KEY);
	try {
		return customParams.getData(key);
	} catch (e) {
		return null;
	} finally {
		key.delete();
	}
}

