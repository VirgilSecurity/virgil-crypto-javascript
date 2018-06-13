import { KeyPair, KeyPairType, HashAlgorithm, assert, IVirgilCryptoWrapper } from './common';
import { toArray } from './utils/toArray';
import {
	VirgilPrivateKey as IVirgilPrivateKey,
	VirgilPublicKey as IVirgilPublicKey,
	VirgilCrypto,
	VirgilCryptoOptions,
	VirgilKeyPair
} from './interfaces';

const _privateKeys = new WeakMap();
const _setValue = WeakMap.prototype.set;
const _getValue = WeakMap.prototype.get;

/**
 * Represents a private key for operations with {@link VirgilCrypto}.
 *
 * `VirgilPrivateKey` objects are not meant to be created directly using the `new` keyword.
 * Use the {@link VirgilCrypto.generateKeys} and {@link VirgilCrypto.importPrivateKey} methods
 * to create `VirgilPrivateKey` instances.
 *
 * @protected
 */
class VirgilPrivateKey implements IVirgilPrivateKey {
	/**
	 * Private key identifier. Note that the private key and its
	 * corresponding public key will have the same identifier.
	 * */
	identifier: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		setPrivateKeyBytes(this, key);
	}
}

/**
 * Represents a public key for operations with {@link VirgilCrypto}.
 *
 * `VirgilPublicKey` objects are not meant to be created directly using the `new` keyword.
 * Use the {@link VirgilCrypto.generateKeys} and {@link VirgilCrypto.importPublicKey} methods
 * to create `VirgilPublicKey` instances.
 *
 * @protected
 */
class VirgilPublicKey implements IVirgilPublicKey {
	/**
	 * Public key identifier. Note that the public key and its
	 * corresponding private key will have the same identifier.
	 * */
	identifier: Buffer;

	/**
	 * The public key material. Unlike the private keys, the public
	 * key material is available as a property of the `PublicKey` object.
	 */
	key: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		this.key = key;
	}
}

/**
 * Gets the private key material of the given private key object from internal buffer.
 * @param {VirgilPrivateKey} privateKey - Private key object.
 * @returns {Buffer} - Private key material.
 *
 * @hidden
 */
function getPrivateKeyBytes(privateKey: VirgilPrivateKey): Buffer {
	return _getValue.call(_privateKeys, privateKey);
}

/**
 * Saves the private key material corresponding to the given private key object into
 * internal buffer.
 *
 * @param {VirgilPrivateKey} privateKey - Private key object.
 * @param {Buffer} bytes - Private key material.
 *
 * @hidden
 */
function setPrivateKeyBytes(privateKey: VirgilPrivateKey, bytes: Buffer) {
	_setValue.call(_privateKeys, privateKey, bytes);
}

/**
 * Factory function producing objects implementing the {@link VirgilCrypto} interface.
 */
export type VirgilCryptoFactory = (options?: VirgilCryptoOptions) => VirgilCrypto;

/**
 * Creates a factory function for objects implementing the {@link VirgilCrypto} interface.
 *
 * @hidden
 *
 * @param {IVirgilCryptoWrapper} cryptoWrapper
 * @returns {(options?: VirgilCryptoOptions) => VirgilCrypto}
 */
export function makeVirgilCryptoFactory (cryptoWrapper: IVirgilCryptoWrapper)
	: VirgilCryptoFactory {

	return function virgilCryptoFactory ({
			useSha256Identifiers = false,
			defaultKeyPairType = KeyPairType.Default
		}: VirgilCryptoOptions = {}
	): VirgilCrypto {
		return {
			get useSha256Identifiers () {
				return useSha256Identifiers;
			},

			get defaultKeyPairType () {
				return defaultKeyPairType;
			},

			generateKeys(type?: KeyPairType) {
				type = type != null ? type : defaultKeyPairType;

				const keyPair = cryptoWrapper.generateKeyPair({ type });
				return wrapKeyPair(keyPair);
			},

			generateKeysFromKeyMaterial(keyMaterial: Buffer, type?: KeyPairType): VirgilKeyPair {
				type = type != null ? type : defaultKeyPairType;

				const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({ keyMaterial, type });
				return wrapKeyPair(keyPair);
			},

			importPrivateKey(rawPrivateKey: Buffer|string, password?: string) {
				assert(
					Buffer.isBuffer(rawPrivateKey) || typeof rawPrivateKey === 'string',
					'Cannot import private key. `rawPrivateKey` must be a Buffer or string in base64'
				);

				rawPrivateKey = Buffer.isBuffer(rawPrivateKey) ? rawPrivateKey : Buffer.from(rawPrivateKey, 'base64');

				if (password) {
					rawPrivateKey = cryptoWrapper.decryptPrivateKey(
						rawPrivateKey, Buffer.from(password, 'utf8')
					);
				}

				const privateKeyDer = cryptoWrapper.privateKeyToDer(rawPrivateKey);
				const publicKeyDer = cryptoWrapper.extractPublicKey(privateKeyDer);
				const identifier = calculateKeypairIdentifier(publicKeyDer);

				return new VirgilPrivateKey(identifier, privateKeyDer);
			},

			exportPrivateKey(privateKey: VirgilPrivateKey, password?: string) {
				const privateKeyValue = getPrivateKeyBytes(privateKey);
				assert(privateKeyValue !== undefined, 'Cannot export private key. `privateKey` is invalid');

				if (password == null) {
					return privateKeyValue;
				}

				return cryptoWrapper.encryptPrivateKey(privateKeyValue, Buffer.from(password, 'utf8'));
			},

			importPublicKey(rawPublicKey: Buffer|string) {
				assert(
					Buffer.isBuffer(rawPublicKey) || typeof rawPublicKey === 'string',
					'Cannot import public key. `rawPublicKey` must be a Buffer'
				);

				rawPublicKey = Buffer.isBuffer(rawPublicKey) ? rawPublicKey : Buffer.from(rawPublicKey, 'base64');
				const publicKeyDer = cryptoWrapper.publicKeyToDer(rawPublicKey);
				const identifier = calculateKeypairIdentifier(publicKeyDer);
				return new VirgilPublicKey(identifier, publicKeyDer);
			},

			exportPublicKey(publicKey: VirgilPublicKey) {
				assert(
					publicKey != null && publicKey.key != null,
					'Cannot import public key. `publicKey` is invalid'
				);

				return publicKey.key;
			},

			encrypt(data: string|Buffer, publicKey: VirgilPublicKey|VirgilPublicKey[]) {
				assert(
					typeof data === 'string' || Buffer.isBuffer(data),
					'Cannot encrypt. `data` must be a string or Buffer'
				);

				const publicKeys = toArray(publicKey);
				assert(
					publicKeys.length > 0,
					'Cannot encrypt. `publicKey` must not be empty'
				);

				data = Buffer.isBuffer(data) ? data : Buffer.from(data);

				return cryptoWrapper.encrypt(data, publicKeys!);
			},

			decrypt(encryptedData: string|Buffer, privateKey: VirgilPrivateKey) {
				assert(
					typeof encryptedData === 'string' || Buffer.isBuffer(encryptedData),
					'Cannot decrypt. `data` must be a Buffer or a string in base64'
				);

				encryptedData = Buffer.isBuffer(encryptedData) ? encryptedData : Buffer.from(encryptedData, 'base64');
				const privateKeyValue = getPrivateKeyBytes(privateKey);
				assert(privateKeyValue !== undefined, 'Cannot decrypt. `privateKey` is invalid');
				return cryptoWrapper.decrypt(encryptedData, {
					identifier: privateKey.identifier,
					key: privateKeyValue
				});
			},

			calculateHash(data: Buffer|string, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
				assert(Buffer.isBuffer(data) || typeof data === 'string',
					'Cannot calculate hash. `data` must be a Buffer or a string in base64');

				data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
				return cryptoWrapper.hash(data, algorithm);
			},

			extractPublicKey(privateKey: VirgilPrivateKey) {
				const privateKeyValue = getPrivateKeyBytes(privateKey);

				assert(
					privateKeyValue !== undefined,
					'Cannot extract public key. `privateKey` is invalid'
				);

				const publicKey = cryptoWrapper.extractPublicKey(privateKeyValue);
				return new VirgilPublicKey(privateKey.identifier, publicKey);
			},

			calculateSignature(data: Buffer|string, privateKey: VirgilPrivateKey) {
				assert(
					Buffer.isBuffer(data) || typeof data === 'string',
					'Cannot calculate signature. `data` must be a Buffer or a string'
				);

				const privateKeyValue = getPrivateKeyBytes(privateKey);

				assert(
					privateKeyValue !== undefined,
					'Cannot calculate signature. `privateKey` is invalid'
				);

				data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

				return cryptoWrapper.sign(data, { key: privateKeyValue });
			},

			verifySignature(data: Buffer|string, signature: Buffer|string, publicKey: VirgilPublicKey) {
				assert(
					Buffer.isBuffer(data) || typeof data === 'string',
					'Cannot verify signature. `data` must be a Buffer or a string'
				);

				assert(
					Buffer.isBuffer(signature) || typeof signature === 'string',
					'Cannot verify signature. `signature` must be a Buffer or a string'
				);

				assert(
					publicKey != null && Buffer.isBuffer(publicKey.key),
					'Cannot verify signature. `publicKey` is invalid'
				);

				data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
				signature = Buffer.isBuffer(signature) ? signature : Buffer.from(signature, 'base64');


				return cryptoWrapper.verify(data, signature, publicKey);
			},

			signThenEncrypt(
				data: Buffer|string,
				signingKey: VirgilPrivateKey,
				encryptionKey: VirgilPublicKey|VirgilPublicKey[])
			{
				assert(
					Buffer.isBuffer(data) || typeof data === 'string',
					'Cannot sign then encrypt. `data` must be a Buffer or a string'
				);

				const signingKeyValue = getPrivateKeyBytes(signingKey);

				assert(signingKeyValue !== undefined, 'Cannot sign then encrypt. `signingKey` is invalid');

				data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

				const encryptionKeys = toArray(encryptionKey);
				assert(
					encryptionKeys.length > 0,
					'Cannot sign then encrypt. `encryptionKey` must not be empty'
				);

				return cryptoWrapper.signThenEncrypt(
					data,
					{
						identifier: signingKey.identifier,
						key: signingKeyValue
					},
					encryptionKeys!
				);
			},

			decryptThenVerify(
				cipherData: Buffer|string,
				decryptionKey: VirgilPrivateKey,
				verificationKey: VirgilPublicKey|VirgilPublicKey[]
			) {
				assert(
					Buffer.isBuffer(cipherData) || typeof cipherData === 'string',
					'Cannot decrypt then verify. `cipherData` must be a Buffer of a string in base64'
				);

				const verificationKeys = toArray(verificationKey);
				assert(
					verificationKeys.length > 0,
					'Cannot decrypt then verify. `verificationKey` must not be empty'
				);

				const decryptionKeyValue = getPrivateKeyBytes(decryptionKey);
				assert(
					decryptionKeyValue !== undefined,
					'Cannot decrypt then verify. `decryptionKey` is invalid'
				);

				cipherData = Buffer.isBuffer(cipherData) ? cipherData : Buffer.from(cipherData, 'base64');

				return cryptoWrapper.decryptThenVerify(
					cipherData,
					{
						identifier: decryptionKey.identifier,
						key: decryptionKeyValue
					},
					verificationKeys!
				);
			},

			getRandomBytes (length: number): Buffer {
				return cryptoWrapper.getRandomBytes(length);
			}
		};

		/**
		 * Calculates the keypair identifier form the public key material.
		 * Takes first 8 bytes of SHA512 of public key DER if `useSHA256Identifiers=false`
		 * and SHA256 of public key der if `useSHA256Identifiers=true`
		 *
		 * @hidden
		 *
		 * @param {Buffer} publicKeyData - Public key material.
		 * @returns {Buffer} Key pair identifier
		 */
		function calculateKeypairIdentifier(publicKeyData: Buffer) {
			if (useSha256Identifiers) {
				return cryptoWrapper.hash(publicKeyData, HashAlgorithm.SHA256);
			} else {
				return cryptoWrapper.hash(publicKeyData, HashAlgorithm.SHA512).slice(0, 8);
			}
		}

		/**
		 * Wraps binary private and public keys into {@link VirgilKeyPair} object.
		 *
		 * @hidden
		 *
		 * @param {KeyPair} keyPair
		 * @returns {VirgilKeyPair}
		 */
		function wrapKeyPair (keyPair: KeyPair) {
			const privateKeyDer = cryptoWrapper.privateKeyToDer(keyPair.privateKey);
			const publicKeyDer = cryptoWrapper.publicKeyToDer(keyPair.publicKey);
			const identifier = calculateKeypairIdentifier(publicKeyDer);

			return {
				privateKey: new VirgilPrivateKey(identifier, privateKeyDer),
				publicKey: new VirgilPublicKey(identifier, publicKeyDer)
			};
		}
	}
}
