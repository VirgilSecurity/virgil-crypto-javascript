import { IPrivateKey } from './interfaces';
import { setPrivateKeyBytes } from './privateKeyUtils';

/**
 * Represents a private key for operations with {@link VirgilCrypto}.
 *
 * `VirgilPrivateKey` objects are not meant to be created directly using the `new` keyword.
 * Use the {@link VirgilCrypto.generateKeys} and {@link VirgilCrypto.importPrivateKey} methods
 * to create `VirgilPrivateKey` instances.
 *
 * @protected
 */
export class VirgilPrivateKey implements IPrivateKey {
	/**
	 * Private key identifier. Note that the private key and its
	 * corresponding public key will have the same identifier.
	 * */
	identifier: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		setPrivateKeyBytes(this, key);
	}
}
