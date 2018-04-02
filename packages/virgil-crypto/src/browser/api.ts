import { lib } from './lib';
import { DecryptionKey, EncryptionKey, KeyPairType, HashAlgorithm } from '../common';
import { toArray } from '../utils/toArray';

/**
 * Decrypt data
 *
 * @param encryptedData {Buffer} - The data to decrypt.
 * @param decryptionKey {DecryptionKey} - Private key with identifier and optional password.
 * @returns {Buffer} - Decrypted data.
 */
export function decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey) {
	const { identifier, privateKey, privateKeyPassword = new Buffer(0) } = decryptionKey;
	const cipher = new lib.VirgilCipher();
	try {
		return cipher.decryptWithKeySafe(encryptedData, identifier, privateKey, privateKeyPassword);
	} finally {
		cipher.delete();
	}
}

/**
 * Decrypts encrypted private key.
 * @param {Buffer} privateKey - Private key to decrypt.
 * @param {Buffer} [password] - Private key password.
 *
 * @returns {Buffer} - Decrypted private key
 * */
export function decryptPrivateKey(privateKey: Buffer, password: Buffer) {
	return lib.VirgilKeyPair.decryptPrivateKeySafe(privateKey, password);
}

/**
 * Encrypt data.
 *
 * @param data {Buffer} - Data to encrypt.
 * @param encryptionKey {EncryptionKey|EncryptionKey[]} - Public key with identifier or an array of
 * public keys with identifiers to encrypt with.
 *
 * @returns {Buffer} - Encrypted data.
 */
export function encrypt(data: Buffer, encryptionKey: EncryptionKey|EncryptionKey[] ) {
	const encryptionKeys = toArray(encryptionKey);
	const cipher = new lib.VirgilCipher();

	try {
		encryptionKeys.forEach(({ identifier, publicKey }: EncryptionKey)  => {
			cipher.addKeyRecipientSafe(identifier, publicKey);
		});
		return cipher.encryptSafe(data, true);
	} finally {
		cipher.delete();
	}
}

/**
 * Encrypts the private key with password
 *
 * @param {Buffer} privateKey - Private key to encrypt
 * @param {Buffer} password - Password to encrypt the private key with
 *
 * @returns {Buffer} - Encrypted private key
 * */
export function encryptPrivateKey(privateKey: Buffer, password: Buffer) {
	return lib.VirgilKeyPair.encryptPrivateKeySafe(privateKey, password);
}

/**
 * Extracts public key out of private key.
 *
 * @param {Buffer} privateKey - Private key to extract from.
 * @param {Buffer} [password] - Private key password if private key is encrypted.
 *
 * @returns {Buffer} - Extracted public key
 * */
export function extractPublicKey(privateKey: Buffer, password: Buffer = new Buffer(0)) {
	return lib.VirgilKeyPair.extractPublicKeySafe(privateKey, password);
}

export type KeyPairOptions = {
	type?: KeyPairType,
	password?: Buffer
};

/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keypair options.
 * @param {Buffer} [options.password] - Private key password (Optional).
 * @param {string} [options.type=] - Keys type identifier (Optional).
 * 		If provided must be one of KeyPairType values.
 * @returns {{publicKey: Buffer, privateKey: Buffer}}
 */
export function generateKeyPair (options: KeyPairOptions = {}) {
	let { type, password = new Buffer(0) } = options;
	let keypair;
	if (type) {
		keypair = lib.VirgilKeyPair.generateSafe(lib.VirgilKeyPair.Type[type], password);
	} else {
		keypair = lib.VirgilKeyPair.generateRecommendedSafe(password);
	}

	return {
		privateKey: keypair.privateKeySafe(),
		publicKey: keypair.publicKeySafe()
	};
}

/**
 * Produces a hash of given data
 *
 * @param {Buffer} data - Data to hash
 * @param {string} [algorithm] - Hash algorithm to use. Default is SHA256
 *
 * @returns {Buffer}
 * */
export function hash(data: Buffer, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
	const virgilHash = new lib.VirgilHash(lib.VirgilHashAlgorithm[algorithm]);
	try {
		return virgilHash.hashSafe(data);
	} finally {
		virgilHash.delete();
	}

}

/**
 * Converts PEM formatted private key to DER format.
 * @param {Buffer} privateKey - Private key in PEM format
 * @param {Buffer} [password] - Private key password, if encrypted.
 * @returns {Buffer} - Private key in DER format.
 * */
export function privateKeyToDer(privateKey: Buffer, password: Buffer = new Buffer(0)) {
	return lib.VirgilKeyPair.privateKeyToDERSafe(privateKey, password);
}

/**
 * Converts PEM formatted public key to DER format.
 * @param {Buffer} publicKey - Public key in PEM format
 * @returns {Buffer} Public key in DER fromat.
 * */
export function publicKeyToDer(publicKey: Buffer) {
	return lib.VirgilKeyPair.publicKeyToDERSafe(publicKey);
}

/**
 * Calculates the digital signature of the given data using the given private key.
 *
 * @param data {Buffer} - Data to sign.
 * @param privateKey {Buffer} - Private key to use.
 * @param [privateKeyPassword] {Buffer} - Optional password the private key is encrypted with.
 * @returns {Buffer} - Digital signature.
 */
export function sign (data: Buffer, privateKey: Buffer, privateKeyPassword = new Buffer(0)) {
	const signer = new lib.VirgilSigner();
	try {
		return signer.signSafe(data, privateKey, privateKeyPassword);
	} finally {
		signer.delete();
	}
}

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
export function verify (data: Buffer, signature: Buffer, publicKey: Buffer) {
	const signer = new lib.VirgilSigner();
	try {
		return signer.verifySafe(data, signature, publicKey);
	} finally {
		signer.delete();
	}
}


