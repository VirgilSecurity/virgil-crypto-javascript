import { toArray } from '../utils/toArray';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { createNativeTypeWrapper } from './createNativeTypeWrapper';
import { KeyPairType } from './KeyPairType';
import { DecryptionKey, EncryptionKey, IVirgilCryptoApi, SigningKey, VerificationKey } from './IVirgilCryptoApi';
import { HashAlgorithm } from './HashAlgorithm';
import { IntegrityCheckFailedError } from './errors';

export type KeyPairOptions = {
	type?: KeyPairType,
	password?: Buffer
};

export function createCryptoApi (lib: any): IVirgilCryptoApi {

	const wrapper = createNativeTypeWrapper(lib);

	wrapper.createSafeInstanceMethods(lib.VirgilCipher, [
		'addKeyRecipient', 'encrypt', 'decryptWithKey', 'addPasswordRecipient', 'decryptWithPassword'
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
		'resetPrivateKeyPassword'
	]);

	lib.createVirgilCipher = () => {
		const cipher = new lib.VirgilCipher();
		if (process.browser) cipher.deleteLater();
		return cipher;
	};
	lib.createVirgilSigner = () => {
		const sha512 = process.browser
			? lib.VirgilHashAlgorithm.SHA512
			: lib.VirgilHash.Algorithm_SHA512;

		const signer = new lib.VirgilSigner(sha512);
		if (process.browser) signer.deleteLater();
		return signer;
	};
	lib.createVirgilHash = (...args: any[]) => {
		const hash = new lib.VirgilHash(...args);
		if (process.browser) hash.deleteLater();
		return hash;
	};

	return {
		generateKeyPair (options: KeyPairOptions = {}) {
			let { type, password = new Buffer(0) } = options;
			let keypair;
			if (type) {
				const libType = process.browser
					? lib.VirgilKeyPairType[type]
					: lib.VirgilKeyPair[`Type_${type}`];
				keypair = lib.VirgilKeyPair.generateSafe(libType, password);
			} else {
				keypair = lib.VirgilKeyPair.generateRecommendedSafe(password);
			}

			return {
				privateKey: keypair.privateKeySafe(),
				publicKey: keypair.publicKeySafe()
			};
		},

		privateKeyToDer(privateKey: Buffer, privateKeyPassword: Buffer = new Buffer(0)) {
			return lib.VirgilKeyPair.privateKeyToDERSafe(privateKey, privateKeyPassword);
		},

		publicKeyToDer(publicKey: Buffer) {
			return lib.VirgilKeyPair.publicKeyToDERSafe(publicKey);
		},

		extractPublicKey(privateKey: Buffer, privateKeyPassword: Buffer = new Buffer(0)) {
			return lib.VirgilKeyPair.extractPublicKeySafe(privateKey, privateKeyPassword);
		},

		encryptPrivateKey(privateKey: Buffer, privateKeyPassword: Buffer) {
			return lib.VirgilKeyPair.encryptPrivateKeySafe(privateKey, privateKeyPassword);
		},

		decryptPrivateKey(privateKey: Buffer, privateKeyPassword: Buffer) {
			return lib.VirgilKeyPair.decryptPrivateKeySafe(privateKey, privateKeyPassword);
		},

		changePrivateKeyPassword(privateKey: Buffer, oldPassword: Buffer, newPassword: Buffer) {
			return lib.VirgilKeyPair.resetPrivateKeyPasswordSafe(privateKey, oldPassword, newPassword);
		},

		hash(data: Buffer, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
			const libAlgorithm = process.browser
				? lib.VirgilHashAlgorithm[algorithm]
				: lib.VirgilHash[`Algorithm_${algorithm}`];

			const virgilHash = lib.createVirgilHash(libAlgorithm);
			return virgilHash.hashSafe(data);
		},

		encryptWithPassword(data: Buffer, password: Buffer) {
			const cipher = lib.createVirgilCipher();
			cipher.addPasswordRecipientSafe(password);
			return cipher.encryptSafe(data, true);
		},

		decryptWithPassword(encryptedData: Buffer, password: Buffer) {
			const cipher = lib.createVirgilCipher();
			return cipher.decryptWithPasswordSafe(encryptedData, password);
		},

		encrypt(data: Buffer, encryptionKey: EncryptionKey|EncryptionKey[] ) {
			const encryptionKeys = toArray(encryptionKey)!;
			const cipher = lib.createVirgilCipher();

			encryptionKeys.forEach(({ identifier, key }: EncryptionKey) => {
				cipher.addKeyRecipientSafe(identifier, key);
			});
			return cipher.encryptSafe(data, true);
		},

		decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey) {
			const { identifier, key, password = new Buffer(0) } = decryptionKey;
			const cipher = lib.createVirgilCipher();
			return cipher.decryptWithKeySafe(encryptedData, identifier, key, password);
		},

		sign (data: Buffer, signingKey: SigningKey) {
			const { key, password = new Buffer(0) } = signingKey;
			const signer = lib.createVirgilSigner();
			return signer.signSafe(data, key, password);
		},

		verify (data: Buffer, signature: Buffer, verificationKey: VerificationKey) {
			const { key } = verificationKey;
			const signer = lib.createVirgilSigner();
			return signer.verifySafe(data, signature, key);
		},

		signThenEncrypt(data: Buffer, signingKey: SigningKey, encryptionKey: EncryptionKey|EncryptionKey[]) {
			const encryptionKeys = toArray(encryptionKey)!;

			const signer = lib.createVirgilSigner();
			const cipher = lib.createVirgilCipher();
			const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);
			const signerIdKey = Buffer.from(DATA_SIGNER_ID_KEY);
			const customParams = cipher.customParams();

			const signature = signer.signSafe(
				data,
				signingKey.key,
				signingKey.password || new Buffer(0)
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
		) {
			const verificationKeys = toArray(verificationKey)!;
			const signer = lib.createVirgilSigner();
			const cipher = lib.createVirgilCipher();
			const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);

			const plainData = cipher.decryptWithKeySafe(
				cipherData,
				decryptionKey.identifier,
				decryptionKey.key,
				decryptionKey.password || new Buffer(0)
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
}
