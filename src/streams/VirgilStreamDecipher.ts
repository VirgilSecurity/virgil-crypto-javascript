import { validatePrivateKey } from '../validators';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { getPrivateKeyBytes } from '../privateKeyUtils';
import { VirgilStreamCipherBase } from './VirgilStreamCipherBase';

/**
 * Class responsible for decryption of streams of data.
 * Follows the same algorithm for decryption as the
 * {@link VirgilCrypto.decrypt} method.
 */
export class VirgilStreamDecipher extends VirgilStreamCipherBase {
	/**
	 * Initializes a new instance of `VirgilStreamDecipher`.
	 * `VirgilStreamDecipher` objects are not meant to be created with the `new`
	 * operator, use {@link VirgilCrypto.createStreamDecipher} to create an
	 * instance.
	 *
	 * @internal
	 *
	 * @param {VirgilPrivateKey} - The {@link VirgilPrivateKey} object to be
	 * used to decrypt the data.
	 */
	constructor (privateKey: VirgilPrivateKey) {
		validatePrivateKey(privateKey);

		super();

		const privateKeyValue = getPrivateKeyBytes(privateKey);
		this.seqCipher.startDecryptionWithKeySafe(
			privateKey.identifier,
			privateKeyValue,
			Buffer.alloc(0)
		);
	}
}
