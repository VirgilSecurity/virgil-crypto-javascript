import { KeyPair, KeyPairType, HashAlgorithm } from './common';
import { toArray } from './utils/toArray';
import { Data } from './interfaces';
import { anyToBuffer, StringEncoding } from './utils/anyToBuffer';
import { cryptoWrapper } from './virgilCryptoWrapper';
import { VirgilPublicKey } from './VirgilPublicKey';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { getPrivateKeyBytes } from './privateKeyUtils';
import { validatePrivateKey, validatePublicKey, validatePublicKeysArray } from './validators';
import { VirgilStreamCipher, VirgilStreamCipherOptions } from './streams/VirgilStreamCipher';
import { VirgilStreamDecipher } from './streams/VirgilStreamDecipher';
import { VirgilStreamSigner } from './streams/VirgilStreamSigner';
import { VirgilStreamVerifier } from './streams/VirgilStreamVerifier';

/**
 * `VirgilCrypto` initialization options.
 */
export interface VirgilCryptoOptions {
	/**
	 * Indicates whether to use old algorithm to calculate keypair identifiers.
	 */
	useSha256Identifiers?: boolean;

	/**
	 * Type of keys to generate by default. Optional. Default is {@link KeyPairType.Default}.
	 */
	defaultKeyPairType?: KeyPairType;
}

/**
 * Object representation of private and public keys pair.
 */
export interface VirgilKeyPair {
	privateKey: VirgilPrivateKey;
	publicKey: VirgilPublicKey;
}

/**
 * Provides implementation of high-level cryptographic operations using Virgil Crypto Library.
 */
export class VirgilCrypto {
	/**
	 * Indicates whether to use old algorithm to calculate keypair identifiers.
	 *
	 * Current algorithm: first 8 bytes of SHA512 hash of public key in DER format.
	 *
	 * Old algorithm: SHA256 hash of public key in DER format.
	 *
	 * Use SHA256 identifiers only if you need to be compatible with version 2 of
	 * this library (i.e. decrypt data that were encrypted using the version 2).
	 *
	 * Default is `false` (new algorithm)
	 */
	public readonly useSha256Identifiers: boolean;

	/**
	 * Type of keys to generate by default.
	 */
	public readonly defaultKeyPairType: KeyPairType;

	/**
	 * Initializes a new instance of {@link VirgilCrypto}.
	 *
	 * @param {Object} [options]
	 * @param {boolean} [options.useSha256Identifiers]
	 * @param {KeyPairType} [options.defaultKeyPairType]
	 */
	constructor({
		useSha256Identifiers = false,
		defaultKeyPairType = KeyPairType.Default
	}: VirgilCryptoOptions = {}) {
		this.useSha256Identifiers = useSha256Identifiers;
		this.defaultKeyPairType = defaultKeyPairType;
	}

	/**
	 * Generates a new key pair.
	 *
	 * @param {KeyPairType} [keyPairType] - Optional type of the key pair.
	 * See {@link KeyPairType} for available options. Default is Ed25519.
	 * @returns {KeyPair} - The newly generated key pair.
	 * */
	generateKeys(type?: KeyPairType) {
		const keyPairType = type != null ? type : this.defaultKeyPairType;
		const keyPair = cryptoWrapper.generateKeyPair({ type: keyPairType });
		return this.wrapKeyPair(keyPair);
	}

	/**
	 * Generates a new key pair from the given key material.
	 * @param {Data} keyMaterial - The data to be used for key generation,
	 * must be strong enough (have high entropy). If `keyMaterial` is a
	 * string, base64 encoding is assumed.
	 * @param {KeyPairType} [type] - Optional type of the key pair.
	 * See {@link KeyPairType} for available options. Default is Ed25519.
	 * @returns {VirgilKeyPair}
	 */
	generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairType): VirgilKeyPair {
		const keyPairType = type != null ? type : this.defaultKeyPairType;
		const keyMaterialBuf = anyToBuffer(keyMaterial, 'base64', 'keyMaterial');

		const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({
			keyMaterial: keyMaterialBuf,
			type: keyPairType
		});
		return this.wrapKeyPair(keyPair);
	}

	/**
	 * Creates a `VirgilPrivateKey` object from private key bytes in PEM or DER format.
	 *
	 * @param {Data} rawPrivateKey - The private key bytes. If `rawPrivateKey` is a
	 * string, base64 encoding is assumed.
	 * @param {string} [password] - Optional password the key bytes are encrypted with.
	 *
	 * @returns {VirgilPrivateKey} - The private key object.
	 * */
	importPrivateKey(rawPrivateKey: Data, password?: string) {
		let rawPrivateKeyBuf = anyToBuffer(rawPrivateKey, 'base64', 'rawPrivateKey');

		if (password) {
			rawPrivateKeyBuf = cryptoWrapper.decryptPrivateKey(
				rawPrivateKeyBuf,
				Buffer.from(password, 'utf8')
			);
		}

		const privateKeyDer = cryptoWrapper.privateKeyToDer(rawPrivateKeyBuf);
		const publicKeyDer = cryptoWrapper.extractPublicKey(privateKeyDer);
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);

		return new VirgilPrivateKey(identifier, privateKeyDer);
	}

	/**
	 * Exports private key material in DER format from the given private key object.
	 *
	 * @param {VirgilPrivateKey} privateKey - The private key object.
	 * @param {string} [password] - Optional password to encrypt the key material with.
	 *
	 * @returns {Buffer} - The private key material in DER format.
	 * */
	exportPrivateKey(privateKey: VirgilPrivateKey, password?: string) {
		validatePrivateKey(privateKey);
		const privateKeyValue = getPrivateKeyBytes(privateKey);

		if (password == null) {
			return privateKeyValue;
		}

		return cryptoWrapper.encryptPrivateKey(privateKeyValue, Buffer.from(password, 'utf8'));
	}

	/**
	 * Creates a `VirgilPublicKey` object from public key material in PEM or DER format.
	 *
	 * @param {Data} rawPublicKey - The public key bytes. If `rawPublicKey` is a
	 * string, base64 encoding is assumed.
	 *
	 * @returns {VirgilPublicKey} - The imported key handle.
	 * */
	importPublicKey(rawPublicKey: Data) {
		const rawPublicKeyBuf = anyToBuffer(rawPublicKey, 'base64', 'rawPublicKey');

		const publicKeyDer = cryptoWrapper.publicKeyToDer(rawPublicKeyBuf);
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);
		return new VirgilPublicKey(identifier, publicKeyDer);
	}

	/**
	 * Exports public key material in DER format from the given public key object.
	 *
	 * @param {VirgilPublicKey} publicKey - The public key object.
	 *
	 * @returns {Buffer} - The public key bytes.
	 * */
	exportPublicKey(publicKey: VirgilPublicKey) {
		validatePublicKey(publicKey);
		return publicKey.key;
	}

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
	 * @param {Data} data - The data to be encrypted. If `data` is a
	 * string, utf-8 encoding is assumed.
	 * @param {VirgilPublicKey|VirgilPublicKey[]} publicKey - Public key or an array of public keys
	 * of the intended recipients.
	 *
	 * @returns {Buffer} - Encrypted data.
	 * */
	encrypt(data: Data, publicKey: VirgilPublicKey|VirgilPublicKey[]) {
		const dataBuf = anyToBuffer(data, 'utf8', 'data');
		const publicKeys = toArray(publicKey);

		validatePublicKeysArray(publicKeys);

		return cryptoWrapper.encrypt(dataBuf, publicKeys);
	}

	/**
	 * Decrypts the data with the given private key following the algorithm below:
	 *
	 * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & the `privateKey`
	 * 2. Computes KDF to obtain AES-256 KEY2 from shared secret
	 * 3. Decrypts KEY1 using AES-256-CBC and KEY2
	 * 4. Decrypts data using KEY1 and AES-256-GCM
	 *
	 * @param {Data} encryptedData - The data to be decrypted. If `encryptedData` is a
	 * string, base64 encoding is assumed.
	 * @param {VirgilPrivateKey} privateKey - The private key to decrypt with.
	 *
	 * @returns {Buffer} - Decrypted data
	 * */
	decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
		const encryptedDataBuf = anyToBuffer(encryptedData, 'base64', 'encryptedData');
		validatePrivateKey(privateKey);
		const privateKeyValue = getPrivateKeyBytes(privateKey);

		return cryptoWrapper.decrypt(encryptedDataBuf, {
			identifier: privateKey.identifier,
			key: privateKeyValue
		});
	}

	/**
	 * Calculates the hash of the given data.
	 *
	 * @param {Data} data - The data to calculate the hash of. If `data` is a
	 * string, utf-8 encoding is assumed.
	 * @param {string} [algorithm] - Optional name of the hash algorithm to use.
	 * See {@link HashAlgorithm} for available options. Default is SHA256.
	 *
	 * @returns {Buffer} - The hash.
	 * */
	calculateHash(data: Data, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
		const dataBuf = anyToBuffer(data, 'utf8', 'data');
		return cryptoWrapper.hash(dataBuf, algorithm);
	}

	/**
	 * Extracts a public key from the private key handle.
	 *
	 * @param {VirgilPrivateKey} privateKey - The private key object to extract from.
	 *
	 * @returns {VirgilPublicKey} - The handle to the extracted public key.
	 * */
	extractPublicKey(privateKey: VirgilPrivateKey) {
		validatePrivateKey(privateKey);
		const privateKeyValue = getPrivateKeyBytes(privateKey);
		const publicKey = cryptoWrapper.extractPublicKey(privateKeyValue);
		return new VirgilPublicKey(privateKey.identifier, publicKey);
	}

	/**
	 * Calculates the signature of the data using the private key.
	 *
	 * NOTE: Returned value contains only digital signature, not data itself.
	 *
	 * NOTE: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
	 *
	 * It's secure to pass raw data here.
	 *
	 * @param {Data} data - The data to be signed. If `data` is a
	 * string, utf-8 encoding is assumed.
	 * @param {VirgilPrivateKey} privateKey - The private key object.
	 *
	 * @returns {Buffer} - The signature.
	 * */
	calculateSignature(data: Data, privateKey: VirgilPrivateKey) {
		const dataBuf = anyToBuffer(data, 'utf8', 'data');
		validatePrivateKey(privateKey);
		const privateKeyValue = getPrivateKeyBytes(privateKey);

		return cryptoWrapper.sign(dataBuf, { key: privateKeyValue });
	}

	/**
	 * Verifies the provided data using the given signature and public key.
	 * Note: Verification algorithm depends on PublicKey type. Default: EdDSA
	 *
	 * @param {Data} data - The data to be verified. If `data` is a
	 * string, utf-8 encoding is assumed.
	 * @param {Data} signature - The signature to verify. If `signature` is a
	 * string, base64 encoding is assumed.
	 * @param {VirgilPublicKey} publicKey - The public key object.
	 *
	 * @returns {boolean} - True or False depending on the validity of the signature for the data
	 * and public key.
	 * */
	verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
		const dataBuf = anyToBuffer(data, 'utf8', 'data');
		const signatureBuf = anyToBuffer(signature, 'base64', 'signature');
		validatePublicKey(publicKey);

		return cryptoWrapper.verify(dataBuf, signatureBuf, publicKey);
	}

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
	 * @param {Data} data - The data to sign and encrypt. If `data` is a
	 * string, utf-8 encoding is assumed.
	 * @param {VirgilPrivateKey} privateKey - The private key to use to calculate signature.
	 * @param {VirgilPublicKey|VirgilPublicKey[]} publicKey - The public key of the intended recipient or an array
	 * of public keys of multiple recipients.
	 *
	 * @returns {Buffer} - Encrypted data with attached signature.
	 * */
	signThenEncrypt(
		data: Data,
		privateKey: VirgilPrivateKey,
		publicKey: VirgilPublicKey|VirgilPublicKey[])
	{
		const dataBuf = anyToBuffer(data, 'utf8', 'data');
		validatePrivateKey(privateKey);
		const privateKeyBytes = getPrivateKeyBytes(privateKey);

		const publicKeys = toArray(publicKey);
		validatePublicKeysArray(publicKeys);

		return cryptoWrapper.signThenEncrypt(
			dataBuf,
			{
				identifier: privateKey.identifier,
				key: privateKeyBytes
			},
			publicKeys
		);
	}

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
	 * @param {Data} encryptedData - The data to be decrypted and verified. If `encryptedData` is a
	 * string, base64 encoding is assumed.
	 * @param {VirgilPrivateKey} privateKey - The private key object to use for decryption.
	 *
	 * @param {(VirgilPublicKey|VirgilPublicKey[])} publicKey - The public key object
	 * or an array of public key objects to use to verify data integrity. If `publicKey`
	 * is an array, the attached signature must be valid for any one of them.
	 *
	 * @returns {Buffer} - Decrypted data iff verification is successful,
	 * otherwise throws {@link IntegrityCheckFailedError}.
	 * */
	decryptThenVerify(
		encryptedData: Data,
		privateKey: VirgilPrivateKey,
		publicKey: VirgilPublicKey|VirgilPublicKey[]
	) {
		const cipherDataBuf = anyToBuffer(encryptedData, 'base64', 'encryptedData');

		const publicKeys = toArray(publicKey);
		validatePublicKeysArray(publicKeys);

		validatePrivateKey(privateKey);
		const privateKeyBytes = getPrivateKeyBytes(privateKey);

		return cryptoWrapper.decryptThenVerify(
			cipherDataBuf,
			{
				identifier: privateKey.identifier,
				key: privateKeyBytes
			},
			publicKeys
		);
	}

	/**
	 * Generates a pseudo-random sequence of bytes of the given length.
	 * @param {number} length - The number of bytes to generate.
	 * @returns {Buffer}
	 */
	getRandomBytes (length: number): Buffer {
		return cryptoWrapper.getRandomBytes(length);
	}

	/**
	 * Same as {@link IVirgilCrypto.signThenEncrypt} but returns the metadata (i.e. public
	 * algorithm parameters used for encryption) as a separate property on the response
	 * object rather than embedded in the encrypted data as regular `signThenEncrypt` does.
	 *
	 * @param {Data} data - The data to sign and encrypt. If `data` is a
	 * string, utf-8 encoding is assumed.
	 * @param {VirgilPrivateKey} privateKey - The private key to use to calculate signature.
	 * @param {VirgilPublicKey | VirgilPublicKey[]} publicKey - The public key of the intended
	 * recipient or an array of public keys of multiple recipients.
	 * @returns {{encryptedData: Buffer; metadata: Buffer}} - Encrypted data and metadata.
	 */
	signThenEncryptDetached (
		data: Data,
		privateKey: VirgilPrivateKey,
		publicKey: VirgilPublicKey|VirgilPublicKey[]) {

		const dataBuf = anyToBuffer(data, 'utf8', 'data');
		validatePrivateKey(privateKey);
		const privateKeyBytes = getPrivateKeyBytes(privateKey);

		const publicKeys = toArray(publicKey);
		validatePublicKeysArray(publicKeys);

		return cryptoWrapper.signThenEncryptDetached(
			dataBuf,
			{
				identifier: privateKey.identifier,
				key: privateKeyBytes
			},
			publicKeys
		);
	}

	/**
	 * Same as {@link IVirgilCrypto.decryptThenVerify} but expects the Virgil Cryptogram
	 * (the content info) to be passed as `contentInfo` parameter instead of be embedded
	 * in the `encryptedData`.
	 * @param {Data} encryptedData - The data to be decrypted and verified. If `encryptedData`
	 * is a string, base64 encoding is assumed.
	 * @param {Data} metadata - The metadata (i.e. public  algorithm parameters used for
	 * encryption) required for decryption.
	 * @param {VirgilPrivateKey} privateKey - The private key object to use for decryption.
	 * @param {VirgilPublicKey | VirgilPublicKey[]} publicKey - The public key object
	 * or an array of public key objects to use to verify data integrity. If the public key
	 * identifier specified in `metadata` does not correspond to the `publicKey` argument
	 * (or any of the keys in the `publicKey` array), an error is thrown.
	 * @returns {Buffer} - Decrypted data iff verification is successful,
	 * otherwise throws {@link IntegrityCheckFailedError}.
	 */
	decryptThenVerifyDetached (
		encryptedData: Data,
		metadata: Data,
		privateKey: VirgilPrivateKey,
		publicKey: VirgilPublicKey|VirgilPublicKey[]) {

		const encryptedDataBuf = anyToBuffer(encryptedData, 'base64', 'encryptedData');
		const metadataBuf = anyToBuffer(metadata, 'base64', 'contentInfo');

		const publicKeys = toArray(publicKey);
		validatePublicKeysArray(publicKeys);

		validatePrivateKey(privateKey);
		const privateKeyBytes = getPrivateKeyBytes(privateKey);

		return cryptoWrapper.decryptThenVerifyDetached(
			encryptedDataBuf,
			metadataBuf,
			{
				identifier: privateKey.identifier,
				key: privateKeyBytes
			},
			publicKeys
		);
	}

	/**
	 * Creates an instance of {@link VirgilStreamCipher} to be used
	 * to encrypt data in chunks using the given `publicKey`.
	 * @param {VirgilPublicKey|VirgilPublicKey[]} publicKey - A single
	 * public key or an array of public keys to encrypt the data with.
	 * @param {Data} [signature] - Optionally add a signature of plain data to the encrypted stream.
	 */
	createStreamCipher (publicKey: VirgilPublicKey|VirgilPublicKey[], options?: VirgilStreamCipherOptions) {
		return new VirgilStreamCipher(publicKey, options);
	}

	/**
	 * Creates an instance of {@link VirgilStreamDecipher} to be used
	 * to decrypt data in chunks using the given `privateKey`.
	 * @param {VirgilPrivateKey} privateKey - The private key to decrypt
	 * the data with.
	 */
	createStreamDecipher (privateKey: VirgilPrivateKey){
		return new VirgilStreamDecipher(privateKey);
	}

	/**
	 * Creates an instance of {@link VirgilStreamSigner} to be used
	 * to calculate signature of data in chunks.
	 */
	createStreamSigner () {
		return new VirgilStreamSigner();
	}

	/**
	 * Creates an instance of {@link VirgilStreamVerifier} to be used
	 * to verify the `signature` for the data in coming in chunks.
	 *
	 * @param {Data} signature - The signature to be verified.
	 * @param {StringEncoding} encoding - If `signature` is a string,
	 * specifies its encoding, otherwise is ignored. Default is 'utf8'.
	 */
	createStreamVerifier (signature: Data, encoding: StringEncoding) {
		return new VirgilStreamVerifier(signature, encoding);
	}

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
	private calculateKeypairIdentifier(publicKeyData: Buffer): Buffer {
		if (this.useSha256Identifiers) {
			return cryptoWrapper.hash(publicKeyData, HashAlgorithm.SHA256);
		}

		return cryptoWrapper.hash(publicKeyData, HashAlgorithm.SHA512).slice(0, 8);
	}

	/**
	 * Wraps binary private and public keys into {@link VirgilKeyPair} object.
	 *
	 * @hidden
	 *
	 * @param {KeyPair} keyPair
	 * @returns {VirgilKeyPair}
	 */
	private wrapKeyPair (keyPair: KeyPair) {
		const privateKeyDer = cryptoWrapper.privateKeyToDer(keyPair.privateKey);
		const publicKeyDer = cryptoWrapper.publicKeyToDer(keyPair.publicKey);
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);

		return {
			privateKey: new VirgilPrivateKey(identifier, privateKeyDer),
			publicKey: new VirgilPublicKey(identifier, publicKeyDer)
		};
	}
}
