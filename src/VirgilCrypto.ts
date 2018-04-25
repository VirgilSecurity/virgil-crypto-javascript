import { cryptoApi } from './node/api';
import { KeyPairType, HashAlgorithm, assert } from './common';
import { toArray } from './utils/toArray';
import { IPrivateKey, IPublicKey, IVirgilCrypto } from './IVirgilCrypto';

export type KeyPair = {
	privateKey: VirgilPrivateKey,
	publicKey: VirgilPublicKey
}

const _privateKeys = new WeakMap();
const _setValue = WeakMap.prototype.set;
const _getValue = WeakMap.prototype.get;

export class VirgilPrivateKey implements IPrivateKey {
	identifier: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		setPrivateKeyBytes(this, key);
	}
}
export class VirgilPublicKey implements IPublicKey {
	identifier: Buffer;
	key: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		this.key = key;
	}
}

function getPrivateKeyBytes(privateKey: VirgilPrivateKey): Buffer {
	return _getValue.call(_privateKeys, privateKey);
}

function setPrivateKeyBytes(privateKey: VirgilPrivateKey, bytes: Buffer) {
	_setValue.call(_privateKeys, privateKey, bytes);
}

export type VirgilCryptoOptions = {
	useSha256Fingerprints?: boolean;
	defaultKeyPairType?: KeyPairType;
}

export class VirgilCrypto implements IVirgilCrypto {
	private readonly useSha256Fingerprints: boolean;
	private readonly defaultKeyPairType: KeyPairType;

	constructor (options: VirgilCryptoOptions = {}) {
		const { useSha256Fingerprints = false, defaultKeyPairType = KeyPairType.Default } = options;
		this.useSha256Fingerprints = useSha256Fingerprints;
		this.defaultKeyPairType = defaultKeyPairType;
	}

	/**
	 * Generates a new key pair.
	 *
	 * @param {KeyPairType} [type] - Optional type of the key pair.
	 * 			See {code: KeyPairType} for available options.
	 * @returns {KeyPair} - The newly generated key pair.
	 * */
	generateKeys(type?: KeyPairType) {
		type = type != null ? type : this.defaultKeyPairType;

		const keyPair = cryptoApi.generateKeyPair({ type });
		const publicKeyDer = cryptoApi.publicKeyToDer(keyPair.publicKey);
		const privateKeyDer = cryptoApi.privateKeyToDer(keyPair.privateKey);
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);

		return {
			privateKey: new VirgilPrivateKey(identifier, privateKeyDer),
			publicKey: new VirgilPublicKey(identifier, publicKeyDer)
		};
	}

	/**
	 * Imports a private key from a Buffer or base64-encoded string
	 * containing key material.
	 *
	 * @param {Buffer|string} rawPrivateKey - The private key material
	 * 			as a {Buffer} or a string in base64.
	 * @param {string} [password] - Optional password the key is
	 * 			encrypted with.
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
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);

		return new VirgilPrivateKey(identifier, privateKeyDer);
	}

	/**
	 * Exports the private key handle into a Buffer containing the key bytes.
	 *
	 * @param {VirgilPrivateKey} privateKey - The private key object.
	 * @param {string} [password] - Optional password to encrypt the key with.
	 *
	 * @returns {Buffer} - The private key bytes.
	 * */
	exportPrivateKey(privateKey: IPrivateKey, password?: string) {
		const privateKeyValue = getPrivateKeyBytes(privateKey as VirgilPrivateKey);
		assert(privateKeyValue !== undefined, 'Cannot export private key. `privateKey` is invalid');

		if (password == null) {
			return privateKeyValue;
		}

		return cryptoApi.encryptPrivateKey(privateKeyValue, Buffer.from(password, 'utf8'));
	}

	/**
	 * Imports a public key from a Buffer or base64-encoded string
	 * containing key material.
	 *
	 * @param {Buffer|string} rawPublicKey - The public key material
	 * 			as a {Buffer} or base64-encoded string.
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
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);
		return new VirgilPublicKey(identifier, publicKeyDer);
	}

	/**
	 * Exports the public key object into a Buffer containing the key bytes.
	 *
	 * @param {VirgilPublicKey} publicKey - The public key object.
	 *
	 * @returns {Buffer} - The public key bytes.
	 * */
	exportPublicKey(publicKey: IPublicKey) {
		const virgilPublicKey = publicKey as VirgilPublicKey;
		assert(
			publicKey != null && virgilPublicKey.key != null,
			'Cannot import public key. `publicKey` is invalid'
		);

		return virgilPublicKey.key;
	}

	/**
	 * Encrypts the data for the recipient(s).
	 *
	 * @param {Buffer|string} data - The data to be encrypted as a {Buffer}
	 * 			or a {string} in UTF8.
	 * @param {VirgilPublicKey|VirgilPublicKey[]} publicKey - Public key or an array of public keys
	 * of the intended recipients.
	 *
	 * @returns {Buffer} - Encrypted data.
	 * */
	encrypt(data: string|Buffer, publicKey: IPublicKey|IPublicKey[]) {
		assert(
			typeof data === 'string' || Buffer.isBuffer(data),
			'Cannot encrypt. `data` must be a string or Buffer'
		);

		const publicKeys = toArray(publicKey) as VirgilPublicKey[];
		assert(
			publicKeys != null && publicKeys.length > 0,
			'Cannot encrypt. `publicKey` must not be empty'
		);

		data = Buffer.isBuffer(data) ? data : Buffer.from(data);

		return cryptoApi.encrypt(data, publicKeys!);
	}

	/**
	 * Decrypts the data with the private key.
	 *
	 * @param {Buffer|string} encryptedData - The data to be decrypted as
	 * 			a {Buffer} or a {string} in base64.
	 * @param {VirgilPrivateKey} privateKey - The private key to decrypt with.
	 *
	 * @returns {Buffer} - Decrypted data
	 * */
	decrypt(encryptedData: string|Buffer, privateKey: IPrivateKey) {
		const virgilPrivateKey = privateKey as VirgilPrivateKey;

		assert(
			typeof encryptedData === 'string' || Buffer.isBuffer(encryptedData),
			'Cannot decrypt. `data` must be a Buffer or a string in base64'
		);

		encryptedData = Buffer.isBuffer(encryptedData) ? encryptedData : Buffer.from(encryptedData, 'base64');
		const privateKeyValue = getPrivateKeyBytes(virgilPrivateKey);
		assert(privateKeyValue !== undefined, 'Cannot decrypt. `privateKey` is invalid');
		return cryptoApi.decrypt(encryptedData, {
			identifier: virgilPrivateKey.identifier,
			key: privateKeyValue
		});
	}

	/**
	 * Calculates the hash of the given data.
	 *
	 * @param {Buffer|string} data - The data to calculate the hash of as a
	 * 			{Buffer} or a {string} in UTF-8.
	 * @param {string} [algorithm] - Optional name of the hash algorithm
	 * 		to use. See { code: virgilCrypto.HashAlgorithm }
	 * 		for available options. Default is SHA256.
	 *
	 * @returns {Buffer} - The hash.
	 * */
	calculateHash(data: Buffer|string, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
		assert(Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot calculate hash. `data` must be a Buffer or a string in base64');

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
		return cryptoApi.hash(data, algorithm);
	}

	/**
	 * Extracts a public key from the private key handle.
	 *
	 * @param {VirgilPrivateKey} privateKey - The private key object to extract from.
	 *
	 * @returns {VirgilPublicKey} - The handle to the extracted public key.
	 * */
	extractPublicKey(privateKey: IPrivateKey) {
		const virgilPrivateKey = privateKey as VirgilPrivateKey;
		const privateKeyValue = getPrivateKeyBytes(virgilPrivateKey);

		assert(
			privateKeyValue !== undefined,
			'Cannot extract public key. `privateKey` is invalid'
		);

		const publicKey = cryptoApi.extractPublicKey(privateKeyValue);
		return new VirgilPublicKey(virgilPrivateKey.identifier, publicKey);
	}

	/**
	 * Calculates the signature of the data using the private key.
	 *
	 * @param {Buffer|string} data - The data to be signed as a Buffer or a string in UTF-8.
	 * @param {VirgilPrivateKey} privateKey - The private key object.
	 *
	 * @returns {Buffer} - The signature.
	 * */
	calculateSignature(data: Buffer|string, privateKey: IPrivateKey) {
		const virgilPrivateKey = privateKey as VirgilPrivateKey;
		assert(
			Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot calculate signature. `data` must be a Buffer or a string'
		);

		const privateKeyValue = getPrivateKeyBytes(virgilPrivateKey);

		assert(
			privateKeyValue !== undefined,
			'Cannot calculate signature. `privateKey` is invalid'
		);

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

		return cryptoApi.sign(data, { key: privateKeyValue });
	}

	/**
	 * Verifies the provided data using the given signature and public key.
	 *
	 * @param {Buffer|string} data - The data to be verified as a {Buffer}
	 * 			or a {string} in UTF-8.
	 * @param {Buffer|string} signature - The signature as a {Buffer} or a
	 * 			{string} in base64.
	 * @param {VirgilPublicKey} publicKey - The public key object.
	 *
	 * @returns {boolean} - True or False depending on the
	 * 			validity of the signature for the data and public key.
	 * */
	verifySignature(data: Buffer|string, signature: Buffer|string, publicKey: IPublicKey) {
		const virgilPublicKey = publicKey as VirgilPublicKey;
		assert(
			Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot verify signature. `data` must be a Buffer or a string'
		);

		assert(
			Buffer.isBuffer(signature) || typeof signature === 'string',
			'Cannot verify signature. `signature` must be a Buffer or a string'
		);

		assert(
			virgilPublicKey != null && Buffer.isBuffer(virgilPublicKey.key),
			'Cannot verify signature. `publicKey` is invalid'
		);

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
		signature = Buffer.isBuffer(signature) ? signature : Buffer.from(signature, 'base64');


		return cryptoApi.verify(data, signature, virgilPublicKey);
	}

	/**
	 * Calculates the signature on the data using the private key,
	 * 		then encrypts the data along with the signature using
	 * 		the public key(s).
	 * @param {Buffer|string} data - The data to sign and encrypt as a Buffer or a string in UTF-8.
	 * @param {VirgilPrivateKey} signingKey - The private key to use to calculate signature.
	 * @param {VirgilPublicKey|VirgilPublicKey[]} encryptionKey - The public key of the intended recipient or an array
	 * of public keys of multiple recipients.
	 *
	 * 	@returns {Buffer} Encrypted data with attached signature.
	 * */
	signThenEncrypt(data: Buffer|string, signingKey: IPrivateKey, encryptionKey: IPublicKey|IPublicKey[]) {
		assert(
			Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot sign then encrypt. `data` must be a Buffer or a string'
		);

		const virgilSigningKey = signingKey as VirgilPrivateKey;
		const signingKeyValue = getPrivateKeyBytes(virgilSigningKey);

		assert(signingKeyValue !== undefined, 'Cannot sign then encrypt. `signingKey` is invalid');

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

		const encryptionKeys = toArray(encryptionKey) as VirgilPublicKey[];
		assert(
			encryptionKeys != null && encryptionKeys.length > 0,
			'Cannot sign then encrypt. `encryptionKey` must not be empty'
		);

		return cryptoApi.signThenEncrypt(
			data,
			{
				identifier: virgilSigningKey.identifier,
				key: signingKeyValue
			},
			encryptionKeys!
		);
	}

	/**
	 * Decrypts the data using the private key, then verifies decrypted data
	 * 		using the attached signature and the given public key.
	 *
	 * 	@param {Buffer|string} cipherData - The data to be decrypted and
	 * 			verified as a Buffer or a string in base64.
	 * 	@param {VirgilPrivateKey} decryptionKey - The private key object to use for decryption.
	 * 	@param {(VirgilPublicKey|VirgilPublicKey[])} verificationKey - The public
	 * 		key object or an array of public key object to use to verify data integrity.
	 * 		If `verificationKey` is an array, the attached signature must be valid for any
	 * 		one of them.
	 *
	 * 	@returns {Buffer} - Decrypted data iff verification is successful,
	 * 			otherwise throws VirgilCryptoError.
	 * */
	decryptThenVerify(cipherData: Buffer|string, decryptionKey: IPrivateKey, verificationKey: IPublicKey|IPublicKey[]) {
		assert(
			Buffer.isBuffer(cipherData) || typeof cipherData === 'string',
			'Cannot decrypt then verify. `cipherData` must be a Buffer of a string in base64'
		);

		const virgilDecryptionKey = decryptionKey as VirgilPrivateKey;
		const verificationKeys = toArray(verificationKey) as VirgilPublicKey[];
		assert(
			verificationKeys != null && verificationKeys.length > 0,
			'Cannot decrypt then verify. `verificationKey` must not be empty'
		);

		const decryptionKeyValue = getPrivateKeyBytes(virgilDecryptionKey);
		assert(
			decryptionKeyValue !== undefined,
			'Cannot decrypt then verify. `decryptionKey` is invalid'
		);

		cipherData = Buffer.isBuffer(cipherData) ? cipherData : Buffer.from(cipherData, 'base64');

		return cryptoApi.decryptThenVerify(
			cipherData,
			{
				identifier: virgilDecryptionKey.identifier,
				key: decryptionKeyValue
			},
			verificationKeys!
		);
	}

	private calculateKeypairIdentifier(publicKeyData: Buffer) {
		if (this.useSha256Fingerprints) {
			return cryptoApi.hash(publicKeyData, HashAlgorithm.SHA256);
		} else {
			return cryptoApi.hash(publicKeyData, HashAlgorithm.SHA512).slice(0, 8);
		}
	}
}
