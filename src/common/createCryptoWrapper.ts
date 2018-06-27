import { toArray } from '../utils/toArray';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { createNativeTypeWrapper } from './createNativeTypeWrapper';
import { KeyPairType } from './KeyPairType';
import { HashAlgorithm } from './HashAlgorithm';
import {
	DecryptionKey,
	EncryptionKey,
	KeyPairFromKeyMaterialOptions,
	KeyPairOptions,
	SigningKey,
	VerificationKey,
	IVirgilCryptoWrapper
} from './IVirgilCryptoWrapper';
import { IntegrityCheckFailedError, VirgilCryptoError, WeakKeyMaterialError } from './errors';

const EMPTY_BUFFER = Buffer.alloc(0);

/**
 * Creates a low level API wrapper for "native" Virgil Crypto library
 * referenced by `lib`.
 *
 * @hidden
 *
 * @param {any} lib - Native Virgil Crypto library (browser or Node.js)
 */
export function createCryptoWrapper (lib: any): IVirgilCryptoWrapper {

	const wrapper = createNativeTypeWrapper(lib);

	wrapper.createSafeInstanceMethods(lib.VirgilCipher, [
		'addKeyRecipient',
		'encrypt',
		'decryptWithKey',
		'addPasswordRecipient',
		'decryptWithPassword',
		'getContentInfo',
		'setContentInfo',
		'keyRecipientExists'
	]);
	wrapper.createSafeInstanceMethods(lib.VirgilSigner, [ 'sign', 'verify' ]);
	wrapper.createSafeInstanceMethods(lib.VirgilHash, [ 'hash' ]);
	wrapper.createSafeInstanceMethods(lib.VirgilCustomParams, [ 'setData', 'getData' ]);
	wrapper.createSafeInstanceMethods(lib.VirgilKeyPair, [ 'privateKey', 'publicKey' ]);
	wrapper.createSafeStaticMethods(lib.VirgilKeyPair, [
		'generate',
		'generateRecommended',
		'decryptPrivateKey',
		'encryptPrivateKey',
		'extractPublicKey',
		'privateKeyToDER',
		'publicKeyToDER',
		'resetPrivateKeyPassword',
		'generateFromKeyMaterial',
		'generateRecommendedFromKeyMaterial'
	]);

	const createVirgilCipher = () => {
		const cipher = new lib.VirgilCipher();
		if (process.browser) cipher.deleteLater();
		return cipher;
	};

	const createVirgilSigner = () => {
		const sha512 = process.browser
			? lib.VirgilHashAlgorithm.SHA512
			: lib.VirgilHash.Algorithm_SHA512;

		const signer = new lib.VirgilSigner(sha512);
		if (process.browser) signer.deleteLater();
		return signer;
	};

	const createVirgilHash = (...args: any[]) => {
		const hash = new lib.VirgilHash(...args);
		if (process.browser) hash.deleteLater();
		return hash;
	};

	const getRandomBytes = (numOfBytes: number) => {
		if (process.browser) {
			const personalInfo = lib.VirgilByteArrayUtils.stringToBytes('');
			const random = new lib.VirgilRandom(personalInfo);

			let byteArr: any;
			try {
				byteArr = random.randomizeBytes(numOfBytes);
				return wrapper.utils.virgilByteArrayToBuffer(byteArr);
			} finally {
				personalInfo.delete();
				random.delete();
				byteArr && byteArr.delete();
			}
		} else {
			const random = new lib.VirgilRandom('');
			return wrapper.utils.virgilByteArrayToBuffer(random.randomize(numOfBytes));
		}
	};


	return {
		generateKeyPair (options: KeyPairOptions = {}) {
			let { type, password = EMPTY_BUFFER } = options;
			let keyPair;
			if (type) {
				keyPair = lib.VirgilKeyPair.generateSafe(getLibKeyPairType(type), password);
			} else {
				keyPair = lib.VirgilKeyPair.generateRecommendedSafe(password);
			}

			return {
				privateKey: keyPair.privateKeySafe(),
				publicKey: keyPair.publicKeySafe()
			};
		},

		generateKeyPairFromKeyMaterial (options: KeyPairFromKeyMaterialOptions) {
			const { keyMaterial, type, password = EMPTY_BUFFER } = options;
			if (keyMaterial.byteLength < 32) {
				throw new WeakKeyMaterialError('Key material is not secure. Expected length >= 32.');
			}

			let keyPair;

			if (type) {
				keyPair = lib.VirgilKeyPair.generateFromKeyMaterialSafe(
					getLibKeyPairType(type),
					keyMaterial,
					password
				);
			} else {
				keyPair = lib.VirgilKeyPair.generateRecommendedFromKeyMaterialSafe(
					keyMaterial,
					password
				);
			}

			return {
				privateKey: keyPair.privateKeySafe(),
				publicKey: keyPair.publicKeySafe()
			};
		},

		privateKeyToDer(privateKey: Buffer, privateKeyPassword: Buffer = EMPTY_BUFFER): Buffer {
			return lib.VirgilKeyPair.privateKeyToDERSafe(privateKey, privateKeyPassword);
		},

		publicKeyToDer(publicKey: Buffer): Buffer {
			return lib.VirgilKeyPair.publicKeyToDERSafe(publicKey);
		},

		extractPublicKey(privateKey: Buffer, privateKeyPassword: Buffer = EMPTY_BUFFER): Buffer {
			return lib.VirgilKeyPair.extractPublicKeySafe(privateKey, privateKeyPassword);
		},

		encryptPrivateKey(privateKey: Buffer, privateKeyPassword: Buffer): Buffer {
			return lib.VirgilKeyPair.encryptPrivateKeySafe(privateKey, privateKeyPassword);
		},

		decryptPrivateKey(privateKey: Buffer, privateKeyPassword: Buffer): Buffer {
			return lib.VirgilKeyPair.decryptPrivateKeySafe(privateKey, privateKeyPassword);
		},

		changePrivateKeyPassword(privateKey: Buffer, oldPassword: Buffer, newPassword: Buffer): Buffer {
			return lib.VirgilKeyPair.resetPrivateKeyPasswordSafe(privateKey, oldPassword, newPassword);
		},

		hash(data: Buffer, algorithm: HashAlgorithm = HashAlgorithm.SHA256): Buffer {
			const libAlgorithm = process.browser
				? lib.VirgilHashAlgorithm[algorithm]
				: lib.VirgilHash[`Algorithm_${algorithm}`];

			const virgilHash = createVirgilHash(libAlgorithm);
			return virgilHash.hashSafe(data);
		},

		encryptWithPassword(data: Buffer, password: Buffer): Buffer {
			const cipher = createVirgilCipher();
			cipher.addPasswordRecipientSafe(password);
			return cipher.encryptSafe(data, true);
		},

		decryptWithPassword(encryptedData: Buffer, password: Buffer): Buffer {
			const cipher = createVirgilCipher();
			return cipher.decryptWithPasswordSafe(encryptedData, password);
		},

		encrypt(data: Buffer, encryptionKey: EncryptionKey|EncryptionKey[] ): Buffer {
			const encryptionKeys = toArray(encryptionKey)!;
			const cipher = createVirgilCipher();

			encryptionKeys.forEach(({ identifier, key }: EncryptionKey) => {
				cipher.addKeyRecipientSafe(identifier, key);
			});
			return cipher.encryptSafe(data, true);
		},

		decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey): Buffer {
			const { identifier, key, password = EMPTY_BUFFER } = decryptionKey;
			const cipher = createVirgilCipher();
			return cipher.decryptWithKeySafe(encryptedData, identifier, key, password);
		},

		sign (data: Buffer, signingKey: SigningKey): Buffer {
			const { key, password = EMPTY_BUFFER } = signingKey;
			const signer = createVirgilSigner();
			return signer.signSafe(data, key, password);
		},

		verify (data: Buffer, signature: Buffer, verificationKey: VerificationKey): boolean {
			const { key } = verificationKey;
			const signer = createVirgilSigner();
			return signer.verifySafe(data, signature, key);
		},

		signThenEncrypt(data: Buffer, signingKey: SigningKey, encryptionKey: EncryptionKey|EncryptionKey[]): Buffer {
			const encryptionKeys = toArray(encryptionKey)!;

			const signer = createVirgilSigner();
			const cipher = createVirgilCipher();
			const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);
			const signerIdKey = Buffer.from(DATA_SIGNER_ID_KEY);
			const customParams = cipher.customParams();

			const signature = signer.signSafe(
				data,
				signingKey.key,
				signingKey.password || EMPTY_BUFFER
			);
			customParams.setDataSafe(signatureKey, signature);

			if (signingKey.identifier != null) {
				customParams.setDataSafe(signerIdKey, signingKey.identifier);
			}

			encryptionKeys.forEach(({ identifier, key }: EncryptionKey) =>
				cipher.addKeyRecipientSafe(identifier, key)
			);

			return cipher.encryptSafe(data, true);
		},

		decryptThenVerify(
			cipherData: Buffer, decryptionKey: DecryptionKey, verificationKey: VerificationKey|VerificationKey[]
		): Buffer {
			const verificationKeys = toArray(verificationKey)!;
			const signer = createVirgilSigner();
			const cipher = createVirgilCipher();
			const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);

			const plainData = cipher.decryptWithKeySafe(
				cipherData,
				decryptionKey.identifier,
				decryptionKey.key,
				decryptionKey.password || EMPTY_BUFFER
			);
			const customParams = cipher.customParams();
			const signature = customParams.getDataSafe(signatureKey);

			let isValid;

			if (verificationKeys.length === 1) {
				isValid = signer.verifySafe(plainData, signature, verificationKeys[0].key);
			} else {
					const signerId = tryGetSignerId(customParams);
				if (signerId !== null) {
					const theKey = verificationKeys.find(
						(key: VerificationKey) => key.identifier != null && key.identifier.equals(signerId)
					);
					if (theKey === undefined) {
						isValid = false;
					} else {
						isValid = signer.verifySafe(plainData, signature, theKey.key);
					}
				} else {
					// no signer id in metadata, try all public keys in sequence
					isValid = verificationKeys.some(
						(key: VerificationKey) => signer.verifySafe(plainData, signature, key.key)
					);
				}
			}


			if (!isValid) {
				throw new IntegrityCheckFailedError('Signature verification has failed.');
			}

			return plainData;
		},

		getRandomBytes,

		signThenEncryptDetached (
			data: Buffer, privateKey: SigningKey, publicKeys: EncryptionKey[]
		): { encryptedData: Buffer, contentInfo: Buffer } {
			const signer = createVirgilSigner();
			const cipher = createVirgilCipher();
			const customParams = cipher.customParams();

			const signature = signer.signSafe(data, privateKey.key, privateKey.password || EMPTY_BUFFER);

			customParams.setDataSafe(Buffer.from(DATA_SIGNATURE_KEY), signature);
			customParams.setDataSafe(Buffer.from(DATA_SIGNER_ID_KEY), privateKey.identifier);

			publicKeys.forEach(({ identifier, key }: EncryptionKey) =>
				cipher.addKeyRecipientSafe(identifier, key)
			);

			const encryptedData = cipher.encryptSafe(data, false);
			const contentInfo = cipher.getContentInfoSafe();
			return { encryptedData, contentInfo };
		},

		decryptThenVerifyDetached (
			encryptedData: Buffer, contentInfo: Buffer, privateKey: DecryptionKey, publicKeys: VerificationKey[]
		): Buffer {
			const signer = createVirgilSigner();
			const cipher = createVirgilCipher();

			cipher.setContentInfoSafe(contentInfo);

			if (!cipher.keyRecipientExistsSafe(privateKey.identifier)) {
				throw new VirgilCryptoError(
					'Wrong private key. The data has not been encrypted with the corresponding public key.'
				);
			}

			const decryptedData = cipher.decryptWithKeySafe(
				encryptedData,
				privateKey.identifier,
				privateKey.key,
				privateKey.password || EMPTY_BUFFER
			);

			const customParams = cipher.customParams();
			const signature = customParams.getDataSafe(Buffer.from(DATA_SIGNATURE_KEY));
			const signerId = tryGetSignerId(customParams);
			if (!signerId) {
				throw new VirgilCryptoError('Signer ID not found in the cryptogram.');
			}

			const matchingPublicKey = publicKeys.find(k => k.identifier!.equals(signerId));
			if (!matchingPublicKey) {
				throw new VirgilCryptoError(
					'Wrong public key(s). The data has not been signed with the corresponding private key(s).'
				);
			}

			if (!signer.verifySafe(decryptedData, signature, matchingPublicKey.key)) {
				throw new VirgilCryptoError('Signature verification failed.');
			}

			return decryptedData;
		}
	};

	function tryGetSignerId(customParams: any): Buffer|null {
		const signerIdKey = Buffer.from(DATA_SIGNER_ID_KEY);
		try {
			return customParams.getDataSafe(signerIdKey);
		} catch (e) {
			return null;
		}
	}

	function getLibKeyPairType (type: KeyPairType) {
		return process.browser
			? lib.VirgilKeyPairType[type]
			: lib.VirgilKeyPair[`Type_${type}`];
	}
}
