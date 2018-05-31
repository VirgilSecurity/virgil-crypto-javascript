import { IVirgilCryptoApi } from './common';
import { KeyPairType, HashAlgorithm, assert } from './common';
import { toArray } from './utils/toArray';
import {
	VirgilPrivateKey as IVirgilPrivateKey,
	VirgilPublicKey as IVirgilPublicKey,
	VirgilCrypto,
	VirgilCryptoOptions
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

export function makeVirgilCryptoFactory (cryptoApi: IVirgilCryptoApi): (options?: VirgilCryptoOptions) => VirgilCrypto {
	return function (options: VirgilCryptoOptions = {}): VirgilCrypto {
		const { useSha256Identifiers = false, defaultKeyPairType = KeyPairType.Default } = options;

		return {
			get useSha256Identifiers () {
				return useSha256Identifiers;
			},

			get defaultKeyPairType () {
				return defaultKeyPairType;
			},

			/**
			 * Generates a new key pair.
			 *
			 * @param {KeyPairType} [type] - Optional type of the key pair.
			 * 			See `KeyPairType` for available options. Default is Ed25519.
			 * @returns {KeyPair} - The newly generated key pair.
			 * */
			generateKeys(type?: KeyPairType) {
				type = type != null ? type : defaultKeyPairType;

				const keyPair = cryptoApi.generateKeyPair({ type });
				const publicKeyDer = cryptoApi.publicKeyToDer(keyPair.publicKey);
				const privateKeyDer = cryptoApi.privateKeyToDer(keyPair.privateKey);
				const identifier = calculateKeypairIdentifier(publicKeyDer);

				return {
					privateKey: new VirgilPrivateKey(identifier, privateKeyDer),
					publicKey: new VirgilPublicKey(identifier, publicKeyDer)
				};
			},

			/**
			 * Creates a `VirgilPrivateKey` object from private key material in PEM or DER format.
			 *
			 * @param {Buffer|string} rawPrivateKey - The private key material as a `Buffer` or a
			 * string in base64.
			 * @param {string} [password] - Optional password the key material is encrypted with.
			 *
			 * @returns {VirgilPrivateKey} - The private key object.
			 * */
			importPrivateKey(rawPrivateKey: Buffer|string, password?: string) {
				assert(
					Buffer.isBuffer(rawPrivateKey) || typeof rawPrivateKey === 'string',
					'Cannot import private key. `rawPrivateKey` must be a Buffer or string in base64'
				);

				rawPrivateKey = Buffer.isBuffer(rawPrivateKey) ? rawPrivateKey : Buffer.from(rawPrivateKey, 'base64');

				if (password) {
					rawPrivateKey = cryptoApi.decryptPrivateKey(
						rawPrivateKey, Buffer.from(password, 'utf8')
					);
				}

				const privateKeyDer = cryptoApi.privateKeyToDer(rawPrivateKey);
				const publicKeyDer = cryptoApi.extractPublicKey(privateKeyDer);
				const identifier = calculateKeypairIdentifier(publicKeyDer);

				return new VirgilPrivateKey(identifier, privateKeyDer);
			},

			/**
			 * Exports private key material in DER format from the given private key object.
			 *
			 * @param {VirgilPrivateKey} privateKey - The private key object.
			 * @param {string} [password] - Optional password to encrypt the key material with.
			 *
			 * @returns {Buffer} - The private key material in DER format.
			 * */
			exportPrivateKey(privateKey: VirgilPrivateKey, password?: string) {
				const privateKeyValue = getPrivateKeyBytes(privateKey);
				assert(privateKeyValue !== undefined, 'Cannot export private key. `privateKey` is invalid');

				if (password == null) {
					return privateKeyValue;
				}

				return cryptoApi.encryptPrivateKey(privateKeyValue, Buffer.from(password, 'utf8'));
			},

			/**
			 * Creates a `VirgilPublicKey` object from public key material in PEM or DER format.
			 *
			 * @param {Buffer|string} rawPublicKey - The public key material as a `Buffer` or
			 * a {string} in base64.
			 *
			 * @returns {VirgilPublicKey} - The imported key handle.
			 * */
			importPublicKey(rawPublicKey: Buffer|string) {
				assert(
					Buffer.isBuffer(rawPublicKey) || typeof rawPublicKey === 'string',
					'Cannot import public key. `rawPublicKey` must be a Buffer'
				);

				rawPublicKey = Buffer.isBuffer(rawPublicKey) ? rawPublicKey : Buffer.from(rawPublicKey, 'base64');
				const publicKeyDer = cryptoApi.publicKeyToDer(rawPublicKey);
				const identifier = calculateKeypairIdentifier(publicKeyDer);
				return new VirgilPublicKey(identifier, publicKeyDer);
			},

			/**
			 * Exports public key material in DER format from the given public key object.
			 *
			 * @param {VirgilPublicKey} publicKey - The public key object.
			 *
			 * @returns {Buffer} - The public key bytes.
			 * */
			exportPublicKey(publicKey: VirgilPublicKey) {
				assert(
					publicKey != null && publicKey.key != null,
					'Cannot import public key. `publicKey` is invalid'
				);

				return publicKey.key;
			},

			/**
			 * Encrypts the data for the given public key(s) following the algorithm below:
			 *
			 * 1. Generates random AES-256 key - KEY1
			 * 2. Encrypts the data with KEY1 using AES-256-GCM
			 * 3. Generates ephemeral keypair for each recipient public key
			 * 4. Uses Diffie-Hellman to obtain shared secret with each recipient public key & ephemeral private key
			 * 5. Computes KDF to obtain AES-256 key - KEY2 - from shared secret for each recipient
			 * 6. Encrypts KEY1 with KEY2 using AES-256-CBC for each recipient
			 *
			 * @param {Buffer|string} data - The data to be encrypted as a `Buffer`.
			 * 			or a `string` in UTF8.
			 * @param {VirgilPublicKey|VirgilPublicKey[]} publicKey - Public key or an array of public keys
			 * of the intended recipients.
			 *
			 * @returns {Buffer} - Encrypted data.
			 * */
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

				return cryptoApi.encrypt(data, publicKeys!);
			},

			/**
			 * Decrypts the data with the given private key following the algorithm below:
			 *
			 * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & the `privateKey`
			 * 2. Computes KDF to obtain AES-256 KEY2 from shared secret
			 * 3. Decrypts KEY1 using AES-256-CBC and KEY2
			 * 4. Decrypts data using KEY1 and AES-256-GCM
			 *
			 * @param {Buffer|string} encryptedData - The data to be decrypted as a `Buffer` or a `string` in base64.
			 * @param {VirgilPrivateKey} privateKey - The private key to decrypt with.
			 *
			 * @returns {Buffer} - Decrypted data
			 * */
			decrypt(encryptedData: string|Buffer, privateKey: VirgilPrivateKey) {
				assert(
					typeof encryptedData === 'string' || Buffer.isBuffer(encryptedData),
					'Cannot decrypt. `data` must be a Buffer or a string in base64'
				);

				encryptedData = Buffer.isBuffer(encryptedData) ? encryptedData : Buffer.from(encryptedData, 'base64');
				const privateKeyValue = getPrivateKeyBytes(privateKey);
				assert(privateKeyValue !== undefined, 'Cannot decrypt. `privateKey` is invalid');
				return cryptoApi.decrypt(encryptedData, {
					identifier: privateKey.identifier,
					key: privateKeyValue
				});
			},

			/**
			 * Calculates the hash of the given data.
			 *
			 * @param {Buffer|string} data - The data to calculate the hash of as a `Buffer` or a `string` in UTF-8.
			 * @param {string} [algorithm] - Optional name of the hash algorithm to use.
			 * See {@link HashAlgorithm} for available options. Default is SHA256.
			 *
			 * @returns {Buffer} - The hash.
			 * */
			calculateHash(data: Buffer|string, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
				assert(Buffer.isBuffer(data) || typeof data === 'string',
					'Cannot calculate hash. `data` must be a Buffer or a string in base64');

				data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
				return cryptoApi.hash(data, algorithm);
			},

			/**
			 * Extracts a public key from the private key handle.
			 *
			 * @param {VirgilPrivateKey} privateKey - The private key object to extract from.
			 *
			 * @returns {VirgilPublicKey} - The handle to the extracted public key.
			 * */
			extractPublicKey(privateKey: VirgilPrivateKey) {
				const privateKeyValue = getPrivateKeyBytes(privateKey);

				assert(
					privateKeyValue !== undefined,
					'Cannot extract public key. `privateKey` is invalid'
				);

				const publicKey = cryptoApi.extractPublicKey(privateKeyValue);
				return new VirgilPublicKey(privateKey.identifier, publicKey);
			},

			/**
			 * Calculates the signature of the data using the private key.
			 *
			 * NOTE: Returned value contains only digital signature, not data itself.
			 *
			 * NOTE: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
			 *
			 * It's secure to pass raw data here.
			 *
			 * @param {Buffer|string} data - The data to be signed as a Buffer or a string in UTF-8.
			 * @param {VirgilPrivateKey} privateKey - The private key object.
			 *
			 * @returns {Buffer} - The signature.
			 * */
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

				return cryptoApi.sign(data, { key: privateKeyValue });
			},

			/**
			 * Verifies the provided data using the given signature and public key.
			 * Note: Verification algorithm depends on PublicKey type. Default: EdDSA
			 *
			 * @param {Buffer|string} data - The data to be verified as a `Buffer` or a `string` in UTF-8.
			 * @param {Buffer|string} signature - The signature as a `Buffer` or a `string` in base64.
			 * @param {VirgilPublicKey} publicKey - The public key object.
			 *
			 * @returns {boolean} - True or False depending on the validity of the signature for the data
			 * and public key.
			 * */
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


				return cryptoApi.verify(data, signature, publicKey);
			},

			/**
			 * Calculates the signature on the data using the private key,
			 * then encrypts the data along with the signature using the public key(s).
			 *
			 * 1. Generates signature depending on the type of private key
			 * 2. Generates random AES-256 key - KEY1
			 * 3. Encrypts both data and signature with KEY1 using AES-256-GCM
			 * 4. Generates ephemeral key pair for each recipient
			 * 5. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
			 * 6. Computes KDF to obtain AES-256 key - KEY2 - from shared secret for each recipient
			 * 7. Encrypts KEY1 with KEY2 using AES-256-CBC for each recipient
			 *
			 * @param {Buffer|string} data - The data to sign and encrypt as a Buffer or a string in UTF-8.
			 * @param {VirgilPrivateKey} signingKey - The private key to use to calculate signature.
			 * @param {VirgilPublicKey|VirgilPublicKey[]} encryptionKey - The public key of the intended recipient or an array
			 * of public keys of multiple recipients.
			 *
			 * @returns {Buffer} - Encrypted data with attached signature.
			 * */
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

				return cryptoApi.signThenEncrypt(
					data,
					{
						identifier: signingKey.identifier,
						key: signingKeyValue
					},
					encryptionKeys!
				);
			},

			/**
			 * Decrypts the data using the private key, then verifies decrypted data
			 * using the attached signature and the given public key.
			 *
			 * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
			 * 2. Computes KDF to obtain AES-256 key - KEY2 - from shared secret
			 * 3. Decrypts KEY1 using AES-256-CBC and KEY2
			 * 4. Decrypts both data and signature using KEY1 and AES-256-GCM
			 * 5. Verifies signature
			 *
			 * @param {Buffer|string} cipherData - The data to be decrypted and
			 * verified as a Buffer or a string in base64.
			 * @param {VirgilPrivateKey} decryptionKey - The private key object to use for decryption.
			 *
			 * @param {(VirgilPublicKey|VirgilPublicKey[])} verificationKey - The public key object
			 * or an array of public key object to use to verify data integrity. If `verificationKey`
			 * is an array, the attached signature must be valid for any one of them.
			 *
			 * @returns {Buffer} - Decrypted data iff verification is successful,
			 * otherwise throws {@link IntegrityCheckFailedError}.
			 * */
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

				return cryptoApi.decryptThenVerify(
					cipherData,
					{
						identifier: decryptionKey.identifier,
						key: decryptionKeyValue
					},
					verificationKeys!
				);
			}
		};

		/**
		 * @hidden
		 * Calculates the keypair identifier form the public key material.
		 * Takes first 8 bytes of SHA512 of public key DER if `useSHA256Identifiers=false`
		 * and SHA256 of public key der if `useSHA256Identifiers=true`
		 *
		 * @param {Buffer} publicKeyData - Public key material.
		 * @returns {Buffer} Key pair identifier
		 */
		function calculateKeypairIdentifier(publicKeyData: Buffer) {
			if (useSha256Identifiers) {
				return cryptoApi.hash(publicKeyData, HashAlgorithm.SHA256);
			} else {
				return cryptoApi.hash(publicKeyData, HashAlgorithm.SHA512).slice(0, 8);
			}
		}
	};
}
