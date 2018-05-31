import { IPrivateKey, IPublicKey, VirgilCrypto, VirgilPrivateKey, VirgilPublicKey } from './interfaces';

/**
 * Class implementing  cryptographic operations required to sign and
 * verify the validity of access tokens (i.e. the `IAccessTokenSigner` interface
 * from {@link https://bit.ly/2GAAH0F|virgil-sdk}),
 * using {@link VirgilCrypto}.
 */
export class VirgilAccessTokenSigner {

	/**
	 * Initializes the new `VirgilAccessTokenSigner`
	 * @param {VirgilCrypto} virgilCrypto - VirgilCrypto instance, providing
	 * implementation of crypto operations.
	 */
	constructor(private readonly virgilCrypto: VirgilCrypto) {
		if (virgilCrypto == null) throw new Error('`virgilCrypto` is required');
	}

	/**
	 * Returns an identifier of the algorithm used for signature calculation
	 * and verification.
	 *
	 * @returns {string} The algorithm identifier. Currently 'VEDS512'
	 */
	getAlgorithm() {
		return 'VEDS512';
	}

	/**
	 * Generates digital signature of the given access token using the given
	 * private key.
	 * @param {Buffer | string} token - The access token bytes.
	 * @param {IPrivateKey} privateKey - The private key object.
	 * @returns {Buffer} - The signature.
	 */
	generateTokenSignature (token: Buffer|string, privateKey: IPrivateKey) {
		return this.virgilCrypto.calculateSignature(token, privateKey as VirgilPrivateKey);
	}

	/**
	 * Verifies the validity of the given signature for the given token and public key.
	 * @param {Buffer | string} token - The token.
	 * @param {Buffer | string} signature - The signature.
	 * @param {IPublicKey} publicKey - The signer's public key.
	 * @returns {boolean} - `true` if signature is valid, otherwise `false`
	 */
	verifyTokenSignature (token: Buffer|string, signature: Buffer|string, publicKey: IPublicKey) {
		return this.virgilCrypto.verifySignature(token, signature, publicKey as VirgilPublicKey);
	}
}
