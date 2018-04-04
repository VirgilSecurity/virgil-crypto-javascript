import { KeyPairType, HashAlgorithm, assert, IVirgilCryptoApi } from './common';
import { toArray } from './utils/toArray';

export type KeyPair = {
	privateKey: PrivateKey,
	publicKey: PublicKey
}

const _privateKeys = new WeakMap();
const _setValue = WeakMap.prototype.set;
const _getValue = WeakMap.prototype.get;

export class PrivateKey {
	identifier: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		setPrivateKeyBytes(this, key);
	}
}
export class PublicKey {
	identifier: Buffer;
	key: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		this.key = key;
	}
}

function getPrivateKeyBytes(privateKey: PrivateKey): Buffer {
	return _getValue.call(_privateKeys, privateKey);
}

function setPrivateKeyBytes(privateKey: PrivateKey, bytes: Buffer) {
	_setValue.call(_privateKeys, privateKey, bytes);
}

export function createVirgilCrypto (cryptoApi: IVirgilCryptoApi) {

	return {
		generateKeys,
		importPrivateKey,
		importPublicKey,
		exportPrivateKey,
		exportPublicKey,
		extractPublicKey,
		encrypt,
		decrypt,
		calculateSignature,
		verifySignature,
		calculateHash,
		signThenEncrypt,
		decryptThenVerify
	};

	/**
	 * Generates a new key pair.
	 *
	 * @param {KeyPairType} [type] - Optional type of the key pair.
	 * 			See {code: KeyPairType} for available options.
	 * @returns {KeyPair} - The newly generated key pair.
	 * */
	function generateKeys(type?: KeyPairType) {
		const keyPair = cryptoApi.generateKeyPair({ type });
		const publicKeyDer = cryptoApi.publicKeyToDer(keyPair.publicKey);
		const privateKeyDer = cryptoApi.privateKeyToDer(keyPair.privateKey);
		const identifier = cryptoApi.hash(publicKeyDer);

		return {
			privateKey: new PrivateKey(identifier, privateKeyDer),
			publicKey: new PublicKey(identifier, publicKeyDer)
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
	 * @returns {PrivateKey} - The private key object.
	 * */
	function importPrivateKey(rawPrivateKey: Buffer|string, password?: string) {
		assert(
			Buffer.isBuffer(rawPrivateKey) || typeof rawPrivateKey === 'string',
			'Cannot import private key. `rawPrivateKey` must be a Buffer or string in base64'
		);

		rawPrivateKey = Buffer.isBuffer(rawPrivateKey) ? rawPrivateKey : Buffer.from(rawPrivateKey, 'base64');

		if (password) {
			rawPrivateKey = cryptoApi.decryptPrivateKey(
				rawPrivateKey, Buffer.from(password, 'utf8'));
		}

		const privateKeyDer = cryptoApi.privateKeyToDer(rawPrivateKey);
		const publicKey = cryptoApi.extractPublicKey(privateKeyDer);
		const publicKeyDer = cryptoApi.publicKeyToDer(publicKey);
		const identifier = cryptoApi.hash(publicKeyDer);

		return new PrivateKey(identifier, privateKeyDer);
	}

	/**
	 * Exports the private key handle into a Buffer containing the key bytes.
	 *
	 * @param {PrivateKey} privateKey - The private key object.
	 * @param {string} [password] - Optional password to encrypt the key with.
	 *
	 * @returns {Buffer} - The private key bytes.
	 * */
	function exportPrivateKey(privateKey: PrivateKey, password?: string) {
		const privateKeyValue = getPrivateKeyBytes(privateKey);
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
	 * @returns {PublicKey} - The imported key handle.
	 * */
	function importPublicKey(rawPublicKey: Buffer|string) {
		assert(
			Buffer.isBuffer(rawPublicKey) || typeof rawPublicKey === 'string',
			'Cannot import public key. `rawPublicKey` must be a Buffer'
		);

		rawPublicKey = Buffer.isBuffer(rawPublicKey) ? rawPublicKey : Buffer.from(rawPublicKey, 'base64');
		const publicKeyDer = cryptoApi.publicKeyToDer(rawPublicKey);
		const identifier = cryptoApi.hash(publicKeyDer);
		return new PublicKey(identifier, publicKeyDer);
	}

	/**
	 * Exports the public key object into a Buffer containing the key bytes.
	 *
	 * @param {PublicKey} publicKey - The public key object.
	 *
	 * @returns {Buffer} - The public key bytes.
	 * */
	function exportPublicKey(publicKey: PublicKey) {
		assert(
			publicKey != null && publicKey.key != null,
			'Cannot import public key. `publicKey` is invalid'
		);

		return publicKey.key;
	}

	/**
	 * Encrypts the data for the recipient(s).
	 *
	 * @param {Buffer|string} data - The data to be encrypted as a {Buffer}
	 * 			or a {string} in UTF8.
	 * @param {PublicKey|PublicKey[]} publicKey - Public key or an array of public keys
	 * of the intended recipients.
	 *
	 * @returns {Buffer} - Encrypted data.
	 * */
	function encrypt(data: string|Buffer, publicKey: PublicKey|PublicKey[]) {
		assert(
			typeof data === 'string' || Buffer.isBuffer(data),
			'Cannot encrypt. `data` must be a string or Buffer'
		);

		const publicKeys = toArray(publicKey);
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
	 * @param {PrivateKey} privateKey - The private key to decrypt with.
	 *
	 * @returns {Buffer} - Decrypted data
	 * */
	function decrypt(encryptedData: string|Buffer, privateKey: PrivateKey) {
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
	function calculateHash(data: Buffer|string, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
		assert(Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot calculate hash. `data` must be a Buffer or a string in base64');

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
		return cryptoApi.hash(data, algorithm);
	}

	/**
	 * Extracts a public key from the private key handle.
	 *
	 * @param {PrivateKey} privateKey - The private key object to extract from.
	 *
	 * @returns {PublicKey} - The handle to the extracted public key.
	 * */
	function extractPublicKey(privateKey: PrivateKey) {
		const privateKeyValue = getPrivateKeyBytes(privateKey);

		assert(
			privateKeyValue !== undefined,
			'Cannot extract public key. `privateKey` is invalid'
		);

		const publicKey = cryptoApi.extractPublicKey(privateKeyValue);
		return new PublicKey(privateKey.identifier, publicKey);
	}

	/**
	 * Calculates the signature of the data using the private key.
	 *
	 * @param {Buffer|string} data - The data to be signed as a Buffer or a string in UTF-8.
	 * @param {PrivateKey} privateKey - The private key object.
	 *
	 * @returns {Buffer} - The signature.
	 * */
	function calculateSignature(data: Buffer|string, privateKey: PrivateKey) {
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
	}

	/**
	 * Verifies the provided data using the given signature and public key.
	 *
	 * @param {Buffer|string} data - The data to be verified as a {Buffer}
	 * 			or a {string} in UTF-8.
	 * @param {Buffer|string} signature - The signature as a {Buffer} or a
	 * 			{string} in base64.
	 * @param {PublicKey} publicKey - The public key object.
	 *
	 * @returns {boolean} - True or False depending on the
	 * 			validity of the signature for the data and public key.
	 * */
	function verifySignature(data: Buffer|string, signature: Buffer|string, publicKey: PublicKey) {
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
	}

	/**
	 * Calculates the signature on the data using the private key,
	 * 		then encrypts the data along with the signature using
	 * 		the public key(s).
	 * @param {Buffer|string} data - The data to sign and encrypt as a Buffer or a string in UTF-8.
	 * @param {PrivateKey} signingKey - The private key to use to calculate signature.
	 * @param {PublicKey|PublicKey[]} encryptionKey - The public key of the intended recipient or an array
	 * of public keys of multiple recipients.
	 *
	 * 	@returns {Buffer} Encrypted data with attached signature.
	 * */
	function signThenEncrypt(data: Buffer|string, signingKey: PrivateKey, encryptionKey: PublicKey|PublicKey[]) {
		assert(
			Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot sign then encrypt. `data` must be a Buffer or a string'
		);

		const signingKeyValue = getPrivateKeyBytes(signingKey);

		assert(signingKeyValue !== undefined, 'Cannot sign then encrypt. `signingKey` is invalid');

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

		const encryptionKeys = toArray(encryptionKey);
		assert(
			encryptionKeys != null && encryptionKeys.length > 0,
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
	}

	/**
	 * Decrypts the data using the private key, then verifies decrypted data
	 * 		using the attached signature and the given public key.
	 *
	 * 	@param {Buffer|string} cipherData - The data to be decrypted and
	 * 			verified as a Buffer or a string in base64.
	 * 	@param {PrivateKey} decryptionKey - The private key object to use for decryption.
	 * 	@param {(PublicKey|PublicKey[])} verificationKey - The public
	 * 		key object or an array of public key object to use to verify data integrity.
	 * 		If `verificationKey` is an array, the attached signature must be valid for any
	 * 		one of them.
	 *
	 * 	@returns {Buffer} - Decrypted data iff verification is successful,
	 * 			otherwise throws VirgilCryptoError.
	 * */
	function decryptThenVerify(cipherData: Buffer|string, decryptionKey: PrivateKey, verificationKey: PublicKey|PublicKey[]) {
		assert(
			Buffer.isBuffer(cipherData) || typeof cipherData === 'string',
			'Cannot decrypt then verify. `cipherData` must be a Buffer of a string in base64'
		);

		const verificationKeys = toArray(verificationKey);
		assert(
			verificationKeys != null && verificationKeys.length > 0,
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
}
