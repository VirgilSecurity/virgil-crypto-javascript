import {
	DecryptionKey,
	EncryptionKey,
	KeyPairType,
	HashAlgorithm,
	SigningKey,
	VerificationKey,
	VirgilCryptoError
} from './index';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { toArray } from '../utils/toArray';
import { IVirgilCryptoApi } from './IVirgilCryptoApi';
import { createNativeTypeWrapper } from './createNativeTypeWrapper';

export type KeyPairOptions = {
	type?: KeyPairType,
	password?: Buffer
};

export function createCryptoApi (lib: any): IVirgilCryptoApi {

	const wrapper = createNativeTypeWrapper(lib);

	wrapper.createSafeInstanceMethods(lib.VirgilCipher, [ 'addKeyRecipient', 'encrypt', 'decryptWithKey' ]);
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
		'publicKeyToDER'
	]);

	lib.createVirgilCipher = () => {
		const cipher = new lib.VirgilCipher();
		if (process.browser) cipher.deleteLater();
		return cipher;
	};
	lib.createVirgilSigner = () => {
		const signer = new lib.VirgilSigner();
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

		privateKeyToDer(privateKey: Buffer, password: Buffer = new Buffer(0)) {
			return lib.VirgilKeyPair.privateKeyToDERSafe(privateKey, password);
		},

		publicKeyToDer(publicKey: Buffer) {
			return lib.VirgilKeyPair.publicKeyToDERSafe(publicKey);
		},

		extractPublicKey(privateKey: Buffer, password: Buffer = new Buffer(0)) {
			return lib.VirgilKeyPair.extractPublicKeySafe(privateKey, password);
		},

		encryptPrivateKey(privateKey: Buffer, password: Buffer) {
			return lib.VirgilKeyPair.encryptPrivateKeySafe(privateKey, password);
		},

		decryptPrivateKey(privateKey: Buffer, password: Buffer) {
			return lib.VirgilKeyPair.decryptPrivateKeySafe(privateKey, password);
		},

		hash(data: Buffer, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
			const libAlgorithm = process.browser
				? lib.VirgilHashAlgorithm[algorithm]
				: lib.VirgilHash[`Algorithm_${algorithm}`];

			const virgilHash = lib.createVirgilHash(libAlgorithm);
			return virgilHash.hashSafe(data);
		},

		encrypt(data: Buffer, encryptionKey: EncryptionKey|EncryptionKey[] ) {
			const encryptionKeys = toArray(encryptionKey);
			const cipher = lib.createVirgilCipher();

			encryptionKeys.forEach(({ identifier, publicKey }: EncryptionKey)  => {
				cipher.addKeyRecipientSafe(identifier, publicKey);
			});
			return cipher.encryptSafe(data, true);
		},

		decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey) {
			const { identifier, privateKey, privateKeyPassword = new Buffer(0) } = decryptionKey;
			const cipher = lib.createVirgilCipher();
			return cipher.decryptWithKeySafe(encryptedData, identifier, privateKey, privateKeyPassword);
		},

		sign (data: Buffer, privateKey: Buffer, privateKeyPassword = new Buffer(0)) {
			const signer = lib.createVirgilSigner();
			return signer.signSafe(data, privateKey, privateKeyPassword);
		},

		verify (data: Buffer, signature: Buffer, publicKey: Buffer) {
			const signer = lib.createVirgilSigner();
			return signer.verifySafe(data, signature, publicKey);
		},

		signThenEncrypt(data: Buffer, signingKey: SigningKey, encryptionKey: EncryptionKey|EncryptionKey[]) {
			const encryptionKeys = toArray(encryptionKey);

			const signer = lib.createVirgilSigner();
			const cipher = lib.createVirgilCipher();
			const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);
			const signerIdKey = Buffer.from(DATA_SIGNER_ID_KEY);
			const customParams = cipher.customParams();

			const signature = signer.signSafe(
				data,
				signingKey.privateKey,
				signingKey.privateKeyPassword || new Buffer(0)
			);
			customParams.setDataSafe(signatureKey, signature);

			if (signingKey.identifier) {
				customParams.setDataSafe(signerIdKey, signingKey.identifier);
			}

			encryptionKeys.forEach((key: EncryptionKey) =>
				cipher.addKeyRecipientSafe(key.identifier, key.publicKey)
			);

			return cipher.encryptSafe(data, true);
		},

		decryptThenVerify(
			cipherData: Buffer, decryptionKey: DecryptionKey, verificationKey: VerificationKey|VerificationKey[]
		) {
			const verificationKeys = toArray(verificationKey);
			const signer = lib.createVirgilSigner();
			const cipher = lib.createVirgilCipher();
			const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);

			const plainData = cipher.decryptWithKeySafe(
				cipherData,
				decryptionKey.identifier,
				decryptionKey.privateKey,
				decryptionKey.privateKeyPassword || new Buffer(0)
			);
			const customParams = cipher.customParams();
			const signature = customParams.getDataSafe(signatureKey);

			let isValid;

			if (verificationKeys.length === 1) {
				isValid = signer.verifySafe(plainData, signature, verificationKeys[0].publicKey);
			} else {
				const signerId = tryGetSignerId(customParams);
				if (signerId !== null) {
					const theKey = verificationKeys.find(
						(key: VerificationKey) => key.identifier.equals(signerId)
					);
					if (theKey === undefined) {
						isValid = false;
					} else {
						isValid = signer.verifySafe(plainData, signature, theKey.publicKey);
					}
				} else {
					// no signer id in metadata, try all public keys in sequence
					isValid = verificationKeys.some(
						(key: VerificationKey) => signer.verifySafe(plainData, signature, key.publicKey)
					);
				}
			}


			if (!isValid) {
				throw new VirgilCryptoError('Signature verification has failed.');
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
