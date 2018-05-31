import { HashAlgorithm } from './common';
import { IPrivateKey, IPublicKey, VirgilCrypto, VirgilPrivateKey, VirgilPublicKey } from './interfaces';

/**
 * Class implementing  cryptographic operations required to create and
 * verify the validity of Virgil Cards (i.e. the `ICardCrypto` interface
 * from {@link https://bit.ly/2GCZLnU|virgil-sdk}), using {@link VirgilCrypto}.
 */
export class VirgilCardCrypto {

	/**
	 * Initializes the new `VirgilCardCrypto`
	 * @param {VirgilCrypto} virgilCrypto - VirgilCrypto instance, providing
	 * implementation of crypto operations.
	 */
	constructor(private readonly virgilCrypto: VirgilCrypto) {
		if (virgilCrypto == null) throw new Error('`virgilCrypto` is required');
	}

	/**
	 * Generates digital signature of the given data using the given private key.
	 *
	 * @param {Buffer | string} data - The data to be signed.
	 * @param {IPrivateKey} privateKey - The private key object.
	 * @returns {Buffer} - The signature data.
	 */
	generateSignature (data: Buffer|string, privateKey: IPrivateKey) {
		return this.virgilCrypto.calculateSignature(data, privateKey as VirgilPrivateKey);
	}

	/**
	 * Verifies the validity of the digital signature for the given data and public key.
	 *
	 * @param {Buffer | string} data - The data that were signed.
	 * @param {Buffer | string} signature - The signature.
	 * @param {IPublicKey} publicKey - The signer's public key.
	 * @returns {boolean} - `true` if signature is valid, otherwise `false`
	 */
	verifySignature (data: Buffer|string, signature: Buffer|string, publicKey: IPublicKey) {
		return this.virgilCrypto.verifySignature(data, signature, publicKey as VirgilPublicKey);
	}

	/**
	 * Exports public key material in DER format from the given public key object.
	 *
	 * @param {IPublicKey} publicKey - The public key object to export the key material from.
	 * @returns {Buffer} - The public key material in DER format.
	 */
	exportPublicKey (publicKey: IPublicKey) {
		return this.virgilCrypto.exportPublicKey(publicKey as VirgilPublicKey);
	}

	/**
	 * Creates a {@link VirgilPublicKey} object from public key material in PEM or DER format.
	 *
	 * @param {Buffer | string} publicKeyData - The public key material. If `publicKeyData` is
	 * a string, base64 encoding is assumed.
	 * @returns {VirgilPublicKey} The public key object.
	 */
	importPublicKey (publicKeyData: Buffer|string) {
		return this.virgilCrypto.importPublicKey(publicKeyData);
	}

	/**
	 * Computes SHA-512 hash of the given data.
	 * @param {Buffer | string} data - The data to be hashed.
	 * @returns {Buffer} - The resulting hash value.
	 */
	generateSha512 (data: Buffer|string) {
		return this.virgilCrypto.calculateHash(data, HashAlgorithm.SHA512);
	}
}
