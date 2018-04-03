import {
	DecryptionKey,
	EncryptionKey,
	HashAlgorithm,
	KeyPairType, SigningKey,
	VerificationKey,
	VirgilCryptoError
} from '../common';
import { lib } from './lib';
import { toArray } from '../utils/toArray';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from '../common/constants';

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
	return cipher.decryptWithKeySafe(encryptedData, identifier, privateKey, privateKeyPassword);
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

	encryptionKeys.forEach(({ identifier, publicKey }: EncryptionKey)  => {
		cipher.addKeyRecipientSafe(identifier, publicKey);
	});
	return cipher.encryptSafe(data, true);
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
		keypair = lib.VirgilKeyPair.generateSafe(lib.VirgilKeyPair[`Type_${type}`], password);
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
	const virgilHash = new lib.VirgilHash(lib.VirgilHash[`Algorithm_${algorithm}`]);
	return virgilHash.hashSafe(data);
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
	return signer.signSafe(data, privateKey, privateKeyPassword);
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
	return signer.verifySafe(data, signature, publicKey);
}

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
export function signThenEncrypt(data: Buffer, signingKey: SigningKey, encryptionKey: EncryptionKey|EncryptionKey[]) {
	const encryptionKeys = toArray(encryptionKey);

	const signer = new lib.VirgilSigner();
	const cipher = new lib.VirgilCipher();
	const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);
	const signerIdKey = Buffer.from(DATA_SIGNER_ID_KEY);
	const customParams = cipher.customParams();

	let signature = signer.signSafe(
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
}

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
export function decryptThenVerify(
	cipherData: Buffer, decryptionKey: DecryptionKey, verificationKey: VerificationKey|VerificationKey[]
) {
	const verificationKeys = toArray(verificationKey);
	const signer = new lib.VirgilSigner();
	const cipher = new lib.VirgilCipher();
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

function tryGetSignerId(customParams: any): Buffer|null {
	const signerIdKey = Buffer.from(DATA_SIGNER_ID_KEY);
	try {
		return customParams.getDataSafe(signerIdKey);
	} catch (e) {
		return null;
	}
}

