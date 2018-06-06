import { KeyPairType } from './index';

/**
 * Private and public keys.
 * @hidden
 */
export type KeyPair = { privateKey: Buffer, publicKey: Buffer };

/**
 * Public key with identifier.
 * @hidden
 * */
export type EncryptionKey = {
	identifier: Buffer,
	key: Buffer
}

/**
 * Private key with identifier and optional password.
 * @hidden
 * */
export type DecryptionKey = {
	identifier: Buffer,
	key: Buffer,
	password?: Buffer
}

/**
 * Same as {DecryptionKey} but identifier field is optional
 * @hidden
 */
export type SigningKey = {
	identifier?: Buffer
	key: Buffer,
	password?: Buffer
}

/**
 * Same as {EncryptionKey} but identifier field is optional
 * @hidden
 */
export type VerificationKey = {
	identifier?: Buffer,
	key: Buffer
};

/**
 * Key pair generation options.
 * @hidden
 */
export interface KeyPairOptions {
	/**
	 * Type of keys to generate. Optional. Default is {@link KeyPairType.Default}
	 */
	type?: KeyPairType;

	/**
	 * Password to encrypt the private key with. Optional. The private key
	 * is not encrypted by default.
	 */
	password?: Buffer;
}

/**
 * Parameter of {@link IVirgilCryptoApi.generateKeyPairFromKeyMaterial} method.
 * @hidden
 */
export interface KeyPairFromKeyMaterialOptions extends KeyPairOptions {
	/**
	 * The data to be used for key generation, must be strong enough (have high entropy).
	 */
	keyMaterial: Buffer;
}

/**
 * The Virgil Crypto library api wrapper interface.
 * @hidden
 */
export interface IVirgilCryptoApi {

	/**
	 * Generate the key pair - public and private keys
	 *
	 * @param {Object} [options={}] - KeyPair generation options.
	 * @param {Buffer} [options.password] - Private key password (Optional).
	 * @param {string} [options.type] - Keys type identifier (Optional).
	 * If provided must be one of KeyPairType values.
	 * @returns {KeyPair}
	 */
	generateKeyPair(options?: { type?: KeyPairType, password?: Buffer }): KeyPair;

	/**
	 * Generates private and public keys from the given key material.
	 *
	 * @param {KeyPairFromKeyMaterialOptions} options - KeyPair generation options.
	 * @returns {KeyPair}
	 */
	generateKeyPairFromKeyMaterial (options: KeyPairFromKeyMaterialOptions): KeyPair;

	/**
	 * Converts PEM formatted private key to DER format.
	 * @param {Buffer} privateKey - Private key in PEM format
	 * @param {Buffer} [privateKeyPassword] - Private key password, if encrypted.
	 * @returns {Buffer} - Private key in DER format.
	 * */
	privateKeyToDer(privateKey: Buffer, privateKeyPassword?: Buffer): Buffer;

	/**
	 * Converts PEM formatted public key to DER format.
	 * @param {Buffer} publicKey - Public key in PEM format
	 * @returns {Buffer} Public key in DER format.
	 * */
	publicKeyToDer(publicKey: Buffer): Buffer;

	/**
	 * Decrypts encrypted private key.
	 * @param {Buffer} privateKey - Private key to decrypt.
	 * @param {Buffer} [privateKeyPassword] - Private key password.
	 *
	 * @returns {Buffer} - Decrypted private key
	 * */
	decryptPrivateKey(privateKey: Buffer, privateKeyPassword: Buffer): Buffer;

	/**
	 * Extracts public key out of private key.
	 *
	 * @param {Buffer} privateKey - Private key to extract from.
	 * @param {Buffer} [privateKeyPassword] - Private key password if private key is encrypted.
	 *
	 * @returns {Buffer} - Extracted public key
	 * */
	extractPublicKey(privateKey: Buffer, privateKeyPassword?: Buffer): Buffer;

	/**
	 * Encrypts the private key with password
	 *
	 * @param {Buffer} privateKey - Private key to encrypt
	 * @param {Buffer} privateKeyPassword - Password to encrypt the private key with
	 *
	 * @returns {Buffer} - Encrypted private key
	 * */
	encryptPrivateKey(privateKey: Buffer, privateKeyPassword: Buffer): Buffer;

	/**
	 * Changes the password of the private key.
	 * @param {Buffer} privateKey
	 * @param {Buffer} oldPassword
	 * @param {Buffer} newPassword
	 * @returns {Buffer} - Private key encrypted with new password.
	 */
	changePrivateKeyPassword(privateKey: Buffer, oldPassword: Buffer, newPassword: Buffer): Buffer;

	/**
	 * Produces a hash of given data
	 *
	 * @param {Buffer} data - Data to hash
	 * @param {string} [algorithm] - Hash algorithm to use. Default is SHA256
	 *
	 * @returns {Buffer}
	 * */
	hash(data: Buffer, algorithm?: string): Buffer;

	/**
	 * Encrypts the data using the password.
	 * @param {Buffer} data
	 * @param {Buffer} password
	 * @returns {Buffer} - Encrypted data
	 */
	encryptWithPassword(data: Buffer, password: Buffer): Buffer;

	/**
	 * Decrypts the data encrypted with the password.
	 * @param {Buffer} encryptedData
	 * @param {Buffer} password
	 * @returns {Buffer} - Decrypted data
	 */
	decryptWithPassword(encryptedData: Buffer, password: Buffer): Buffer;

	/**
	 * Encrypt data.
	 *
	 * @param data {Buffer} - Data to encrypt.
	 * @param encryptionKey {EncryptionKey|EncryptionKey[]} - Public key with identifier or an array of
	 * public keys with identifiers to encrypt with.
	 *
	 * @returns {Buffer} - Encrypted data.
	 */
	encrypt(data: Buffer, encryptionKey: EncryptionKey|EncryptionKey[]): Buffer;

	/**
	 * Decrypt data
	 *
	 * @param encryptedData {Buffer} - The data to decrypt.
	 * @param decryptionKey {DecryptionKey} - Private key with identifier and optional password.
	 * @returns {Buffer} - Decrypted data.
	 */
	decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey): Buffer;

	/**
	 * Calculates the digital signature of the given data using the given private key.
	 *
	 * @param data {Buffer} - Data to sign.
	 * @param signingKey {SigningKey} - Private key to use.
	 * @returns {Buffer} - Digital signature.
	 */
	sign(data: Buffer, signingKey: SigningKey): Buffer;

	/**
	 * Verifies digital signature of the given data for the given public key.
	 *
	 * @param data {Buffer} - Data to verify.
	 * @param signature {Buffer} - The signature.
	 * @param verificationKey {Buffer} - The public key.
	 *
	 * @returns {boolean} - True if signature is valid for the given public key and data,
	 * otherwise False.
	 */
	verify(data: Buffer, signature: Buffer, verificationKey: VerificationKey): boolean;

	/**
	 * Signs and encrypts the data.
	 *
	 * @param {Buffer} data - Data to sign and encrypt.
	 * @param {SigningKey} signingKey - The private key to use for signature calculation.
	 * @param {EncryptionKey|EncryptionKey[]} encryptionKey - Public key with identifier or an array of
	 * public keys with identifiers to use for encryption.
	 *
	 * @returns {Buffer} Signed and encrypted data.
	 */
	signThenEncrypt(data: Buffer, signingKey: SigningKey, encryptionKey: EncryptionKey|EncryptionKey[]): Buffer;

	/**
	 * Decrypts the given data with private key and verify the signature with
	 * public key.
	 *
	 * @param {Buffer} cipherData - Data to decrypt.
	 * @param {DecryptionKey} decryptionKey - The private key to use for decryption.
	 * @param {VerificationKey|VerificationKey[]} verificationKey - Public key or an array of public
	 * 		keys to use to to verify the signature. If the cipher data
	 * 		contains an identifier of the private key used to calculate the signature,
	 * 		then the public key with that identifier from `verificationKey` array will be
	 * 		used to validate the signature, otherwise ANY one of the keys can validate
	 * 		the signature. If the signature is not valid for ALL of the keys,
	 * 		an exception is thrown.
	 *
	 * @returns {Buffer} Decrypted data
	 * */
	decryptThenVerify(cipherData: Buffer, decryptionKey: DecryptionKey, verificationKey: VerificationKey|VerificationKey[]): Buffer;

	/**
	 * Generates a random byte sequence of the given size.
	 *
	 * @param {number} numOfBytes - Number of bytes to generate.
	 *
	 * @returns {Buffer}
	 */
	getRandomBytes (numOfBytes: number): Buffer;
}
