import { VirgilCrypto, VirgilPrivateKey, VirgilPublicKey } from './VirgilCrypto';
import { IPrivateKey, IPublicKey } from './interfaces';

/**
 * Class implementing  cryptographic operations required to sign and
 * verify the validity of access tokens (i.e. the `IAccessTokenSigner` interface
 * from {@link https://bit.ly/2GAAH0F|virgil-sdk}),
 * using {@link VirgilCrypto}.
 */
export class VirgilAccessTokenSigner {
	private readonly crypto: VirgilCrypto;

	/**
	 * Initializes the new `VirgilAccessTokenSigner`
	 * @param {VirgilCrypto} virgilCrypto - VirgilCrypto instance, providing
	 * implementation of crypto operations. Optional. A new instance will be
	 * created automatically if this parameter is omitted.
	 */
	constructor(virgilCrypto?: VirgilCrypto) {
		this.crypto = virgilCrypto || new VirgilCrypto();
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
		return this.crypto.calculateSignature(token, privateKey as VirgilPrivateKey);
	}

	/**
	 * Verifies the validity of the given signature for the given token and public key.
	 * @param {Buffer | string} token - The token.
	 * @param {Buffer | string} signature - The signature.
	 * @param {IPublicKey} publicKey - The signer's public key.
	 * @returns {boolean} - `true` if signature is valid, otherwise `false`
	 */
	verifyTokenSignature (token: Buffer|string, signature: Buffer|string, publicKey: IPublicKey) {
		return this.crypto.verifySignature(token, signature, publicKey as VirgilPublicKey);
	}
}
