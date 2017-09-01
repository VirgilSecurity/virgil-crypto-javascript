import VC from '../utils/crypto-module';
import { assert, generateErrorFromNativeError } from '../utils/crypto-errors';
import {
	bufferToByteArray,
	toByteArraySafe,
	convertToBufferAndRelease
} from '../utils/crypto-utils';

import {
	makePFSPrivateKey,
	makePFSPublicKey,
	emptyPFSPrivateKey,
	emptyPFSPublicKey
} from './key-utils';

/**
 * @typedef {Object} InitiatorPrivateInfo
 *
 * @description Initiator's data used to start the *initiator's* session.
 *
 * @property {(Buffer|{privateKey:Buffer, password:Buffer})} identityPrivateKey -
 * Initiator's *identity* private key or *identity* private key with password.
 *
 * @property {(Buffer|{privateKey:Buffer, password:Buffer})} ephemeralPrivateKey -
 * Initiator's *ephemeral* private key or *ephemeral* private key with password.
 */

/**
 * @typedef {Object} InitiatorPublicInfo
 *
 * @description Initiator's data used to start the *responder's* session.
 *
 * @property {Buffer} identityPublicKey - Initiator's *identity* public key.
 *
 * @property {Buffer} ephemeralPublicKey - Initiator's *ephemeral* public key.
 */

/**
 * @typedef {Object} ResponderPrivateInfo
 *
 * @description Responder's data used to start the *responder's* session.
 *
 * @property {(Buffer|{privateKey:Buffer, password:Buffer})} identityPrivateKey -
 * Responder's *identity* private key or *identity* private key with password.
 *
 * @property {(Buffer|{privateKey:Buffer, password:Buffer})} longTermPrivateKey -
 * Responder's *long term* private key or *long term* private key with password.
 *
 * @property {(Buffer|{privateKey:Buffer, password:Buffer})} [oneTimePrivateKey] -
 * Responder's *one time* private key or *one time* private key with password.
 * Optional unless the corresponding public key had been used to start
 * *initiator's* session.
 *
 */

/**
 * @typedef {Object} ResponderPublicInfo
 *
 * @description Responder's data used to start the *initiator's* session.
 *
 * @property {Buffer} identityPublicKey - Responder's *identity* public key.
 *
 * @property {Buffer} longTermPublicKey - Responder's *long term* public key.
 *
 * @property {Buffer} [oneTimePublicKey] - Optional responder's *one time* public key.
 */

/**
 * @typedef {Object} PFSEncryptedMessage
 *
 * @description Object representing encrypted message with metadata.
 *
 * @property {Buffer} sessionId
 * @property {Buffer} salt
 * @property {Buffer} ciphertext
 */

/**
 * @typedef {Object} PFSSession
 *
 * @description Object representing PFS Session state.
 *
 * @property {Buffer} id - Session identifier.
 *
 * @property {Buffer} encryptionSecretKey - Shared secret key used for encryption.
 * @property {Buffer} decryptionSecretKey - Shared secret key used for decryption.
 * @property {Buffer} additionalData - Additional authentication data.
 */

/**
 * Class providing means to encrypt and decrypt messages with perfect forward
 * secrecy.
 */
export default class VirgilPFS {

	constructor() {
		this.pfs = new VC.VirgilPFS();
	}

	/**
	 * Starts an "initiator" session. The session is saved in this
	 * object's internal state.
	 *
	 * @param {InitiatorPrivateInfo} initiatorPrivateInfo - Initiator's private data.
	 * @param {ResponderPublicInfo} responderPublicInfo - Responder's public data.
	 * @param {Buffer} [additionalData] - Optional additional authentication data.
	 */
	startInitiatorSession({ initiatorPrivateInfo, responderPublicInfo, additionalData = null }) {
		const initiatorIdentityKey = makePFSPrivateKey(initiatorPrivateInfo.identityPrivateKey);
		assert(
			initiatorIdentityKey !== null,
			badPrivateKeyError('startInitiatorSession', 'initiatorPrivateInfo.identityPrivateKey')
		);

		const initiatorEphemeralKey = makePFSPrivateKey(initiatorPrivateInfo.ephemeralPrivateKey);
		assert(
			initiatorEphemeralKey !== null,
			badPrivateKeyError('startInitiatorSession', 'initiatorPrivateInfo.ephemeralPrivateKey')
		);

		const responderIdentityPubkey = makePFSPublicKey(responderPublicInfo.identityPublicKey);
		assert(
			responderIdentityPubkey !== null,
			badPublicKeyError('startInitiatorSession', 'responderPublicInfo.identityPublicKey')
		);

		const responderLongTermPubkey = makePFSPublicKey(responderPublicInfo.longTermPublicKey);
		assert(
			responderLongTermPubkey !== null,
			badPublicKeyError('startInitiatorSession', 'responderPublicInfo.longTermPublicKey')
		);

		const responderOneTimePublicKey = responderPublicInfo.oneTimePublicKey
			? makePFSPublicKey(responderPublicInfo.oneTimePublicKey)
			: emptyPFSPublicKey();
		assert(
			responderOneTimePublicKey !== null,
			badPublicKeyError('startInitiatorSession', 'responderPublicInfo.oneTimePublicKey')
		);

		const initiatorInfoNative = new VC.VirgilPFSInitiatorPrivateInfo(
			initiatorIdentityKey,
			initiatorEphemeralKey
		);

		const responderInfoNative = new VC.VirgilPFSResponderPublicInfo(
			responderIdentityPubkey,
			responderLongTermPubkey,
			responderOneTimePublicKey
		);

		const additionalDataNative = additionalData
			? bufferToByteArray(additionalData)
			: new VC.VirgilByteArray();

		try {
			this.pfs.startInitiatorSession(
				initiatorInfoNative,
				responderInfoNative,
				additionalDataNative
			);
		} catch (e) {
			throw generateErrorFromNativeError(e);
		} finally {
			initiatorIdentityKey.delete();
			initiatorEphemeralKey.delete();
			responderIdentityPubkey.delete();
			responderLongTermPubkey.delete();
			responderOneTimePublicKey.delete();
			initiatorInfoNative.delete();
			responderInfoNative.delete();
			additionalDataNative.delete();
		}

	}

	/**
	 * Starts a "responder" session. The session is saved in this object's
	 * internal state.
	 *
	 * @param {ResponderPrivateInfo} responderPrivateInfo - Responder's private data.
	 * @param {InitiatorPublicInfo} initiatorPublicInfo - Initiator's public data.
	 * @param {Buffer} [additionalData] - Optional additional authentication data.
	 */
	startResponderSession({ responderPrivateInfo, initiatorPublicInfo, additionalData }) {
		const responderIdentityKey = makePFSPrivateKey(responderPrivateInfo.identityPrivateKey);
		assert(
			responderIdentityKey !== null,
			badPrivateKeyError('startResponderSession', 'responderPrivateInfo.identityPrivateKey')
		);

		const responderLongTermKey = makePFSPrivateKey(responderPrivateInfo.longTermPrivateKey);
		assert(
			responderLongTermKey !== null,
			badPrivateKeyError('startResponderSession', 'responderPrivateInfo.longTermPrivateKey')
		);

		const responderOneTimeKey = responderPrivateInfo.oneTimePrivateKey
			? makePFSPrivateKey(responderPrivateInfo.oneTimePrivateKey)
			: emptyPFSPrivateKey();
		assert(
			responderOneTimeKey !== null,
			badPrivateKeyError('startResponderSession', 'responderPrivateInfo.oneTimePrivateKey')
		);

		const initiatorIdentityPubkey = makePFSPublicKey(initiatorPublicInfo.identityPublicKey);
		assert(
			initiatorIdentityPubkey !== null,
			badPublicKeyError('startResponderSession', 'initiatorPublicInfo.identityPublicKey')
		);

		const initiatorEphemeralPubkey = makePFSPublicKey(initiatorPublicInfo.ephemeralPublicKey);
		assert(
			initiatorEphemeralPubkey !== null,
			badPublicKeyError('startResponderSession', 'initiatorPublicInfo.ephemeralPublicKey')
		);

		const responderPrivateInfoNative = new VC.VirgilPFSResponderPrivateInfo(
			responderIdentityKey,
			responderLongTermKey,
			responderOneTimeKey
		);

		const initiatorPublicInfoNative = new VC.VirgilPFSInitiatorPublicInfo(
			initiatorIdentityPubkey,
			initiatorEphemeralPubkey
		);

		const additionalDataNative = additionalData
			? bufferToByteArray(additionalData)
			: new VC.VirgilByteArray();

		try {
			this.pfs.startResponderSession(
				responderPrivateInfoNative,
				initiatorPublicInfoNative,
				additionalDataNative
			);
		} catch (e) {
			throw generateErrorFromNativeError(e);
		} finally {
			responderIdentityKey.delete();
			responderLongTermKey.delete();
			responderOneTimeKey.delete();
			initiatorIdentityPubkey.delete();
			initiatorEphemeralPubkey.delete();
			responderPrivateInfoNative.delete();
			initiatorPublicInfoNative.delete();
			additionalDataNative.delete();
		}
	}

	/**
	 * Encrypts the given data using internal session key.
	 * The session must be initialized before this method is called.
	 *
	 * @param {Buffer} data - data to encrypt.
	 *
	 * @returns {PFSEncryptedMessage}
	 */
	encrypt(data) {
		const dataBytes = toByteArraySafe(data);
		assert(
			dataBytes !== null,
			'encrypt(): Invalid argument "data". Expected Buffer or a string.'
		);

		let encryptedMessage;
		try {
			encryptedMessage = this.pfs.encrypt(dataBytes);
		} catch(e) {
			throw generateErrorFromNativeError(e);
		} finally {
			dataBytes.delete();
		}

		const sessionId = convertToBufferAndRelease(encryptedMessage.getSessionIdentifier());
		const salt = convertToBufferAndRelease(encryptedMessage.getSalt());
		const ciphertext = convertToBufferAndRelease(encryptedMessage.getCipherText());

		encryptedMessage.delete();

		return { sessionId, salt, ciphertext };
	}

	/**
	 * Decrypts the given message using internal session key.
	 * The session must be initialized before this method is called.
	 *
	 * @param {PFSEncryptedMessage} - Message to decrypt.
	 *
	 * @returns {Buffer} - Decrypted data.
	 *
	 * @throws {VirgilCryptoError} In cases when message cannot be decrypted.
	 */
	decrypt({ sessionId, salt, ciphertext}) {
		const sessionIdArray = bufferToByteArray(sessionId);
		const saltArray = bufferToByteArray(salt);
		const ciphertextArray = bufferToByteArray(ciphertext);

		const encryptedMessage = new VC.VirgilPFSEncryptedMessage(
			sessionIdArray,
			saltArray,
			ciphertextArray
		);

		try {
			const dataArray = this.pfs.decrypt(encryptedMessage);
			return convertToBufferAndRelease(dataArray);
		} catch (e) {
			throw generateErrorFromNativeError(e);
		} finally {
			sessionIdArray.delete();
			saltArray.delete();
			ciphertextArray.delete();
			encryptedMessage.delete();
		}
	}

	/**
	 * Returns internal session's identifier, or null if no session
	 * has been started.
	 *
	 * @returns {Buffer}
	 */
	getSessionId() {
		const session = this.pfs.getSession();
		if (!session || session.isEmpty()) {
			return null;
		}

		try {
			return convertToBufferAndRelease(session.getIdentifier());
		} finally {
			session.delete();
		}
	}

	/**
	 * Returns internal session state, or null if no session has been started.
	 *
	 * @returns {PFSSession}
	 */
	getSession() {
		const session = this.pfs.getSession();
		if (!session || session.isEmpty()) {
			return null;
		}

		try {
			return {
				id: convertToBufferAndRelease(session.getIdentifier()),
				encryptionSecretKey: convertToBufferAndRelease(session.getEncryptionSecretKey()),
				decryptionSecretKey: convertToBufferAndRelease(session.getDecryptionSecretKey()),
				additionalData: convertToBufferAndRelease(session.getAdditionalData())
			};
		} finally {
			session.delete();
		}
	}

	/**
	 * Frees the memory used to store internal object's state. Manual memory
	 * freeing is required because GC cannot collect objects in Emscripten's
	 * Module memory. Make sure to call this method when the pfs object is
	 * no longer needed.
	 */
	destroy() {
		this.pfs.delete();
	}
}

const badPrivateKeyError = (method, argument) => {
	return `${method}(): Invalid argument "${argument}". Expected a Buffer or a hash with "privateKey" property.`;
};

const badPublicKeyError = (method, argument) => {
	return `${method}(): Invalid argument "${argument}". Expected a Buffer.`;
};
