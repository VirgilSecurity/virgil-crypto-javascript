import {
	KeyPairType,
	DecryptionKey,
	EncryptionKey,
	SigningKey,
	VerificationKey
} from './index';

export interface IVirgilCryptoApi {

	/**
	 * Generate the key pair - public and private keys
	 *
	 * @param {Object} [options={}] - Keypair options.
	 * @param {Buffer} [options.password] - Private key password (Optional).
	 * @param {string} [options.type=] - Keys type identifier (Optional).
	 * 		If provided must be one of KeyPairType values.
	 * @returns {{publicKey: Buffer, privateKey: Buffer}}
	 */
	generateKeyPair(options: { type?: KeyPairType, password?: Buffer }): { privateKey: Buffer, publicKey: Buffer };

	/**
	 * Converts PEM formatted private key to DER format.
	 * @param {Buffer} privateKey - Private key in PEM format
	 * @param {Buffer} [password] - Private key password, if encrypted.
	 * @returns {Buffer} - Private key in DER format.
	 * */
	privateKeyToDer(privateKey: Buffer, password?: Buffer): Buffer;

	/**
	 * Converts PEM formatted public key to DER format.
	 * @param {Buffer} publicKey - Public key in PEM format
	 * @returns {Buffer} Public key in DER fromat.
	 * */
	publicKeyToDer(publicKey: Buffer): Buffer;

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
	 * Decrypts encrypted private key.
	 * @param {Buffer} privateKey - Private key to decrypt.
	 * @param {Buffer} [password] - Private key password.
	 *
	 * @returns {Buffer} - Decrypted private key
	 * */
	decryptPrivateKey(privateKey: Buffer, password: Buffer): Buffer;

	/**
	 * Extracts public key out of private key.
	 *
	 * @param {Buffer} privateKey - Private key to extract from.
	 * @param {Buffer} [password] - Private key password if private key is encrypted.
	 *
	 * @returns {Buffer} - Extracted public key
	 * */
	extractPublicKey(privateKey: Buffer): Buffer;

	/**
	 * Encrypts the private key with password
	 *
	 * @param {Buffer} privateKey - Private key to encrypt
	 * @param {Buffer} password - Password to encrypt the private key with
	 *
	 * @returns {Buffer} - Encrypted private key
	 * */
	encryptPrivateKey(privateKey: Buffer, password: Buffer): Buffer;

	/**
	 * Calculates the digital signature of the given data using the given private key.
	 *
	 * @param data {Buffer} - Data to sign.
	 * @param privateKey {Buffer} - Private key to use.
	 * @param [privateKeyPassword] {Buffer} - Optional password the private key is encrypted with.
	 * @returns {Buffer} - Digital signature.
	 */
	sign(data: Buffer, privateKey: Buffer, privateKeyPassword?: Buffer): Buffer;

	/**
	 * Verifies digital signature of the given data for the given public key.
	 *
	 * @param data {Buffer} - Data to verify.
	 * @param signature {Buffer} - The signature.
	 * @param publicKey {Buffer} - The public key.
	 *
	 * @returns {boolean} - True if signature is valid for the given public key and data,
	 * otherwise False.
	 */
	verify(data: Buffer, signature: Buffer, publicKey: Buffer): boolean;

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
}
