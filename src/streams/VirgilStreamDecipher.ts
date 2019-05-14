import { validatePrivateKey } from '../validators';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { getPrivateKeyBytes } from '../privateKeyUtils';
import { VirgilStreamCipherBase } from './VirgilStreamCipherBase';
import { DATA_SIGNATURE_KEY } from '../common/constants';
import { StringEncoding } from '../utils/anyToBuffer';

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

	/**
	 * Get signature from content_info if it was added on encryption phase.
	 */
	getSignature(): Buffer | null {
		if (!this.isFinished) {
			throw new Error('Illegal state. Cannot get signature before the `final` method has been called.');
		}
		const customParams = this.seqCipher.customParams();
		let signature: Buffer;
		try {
			signature = customParams.getDataSafe(Buffer.from(DATA_SIGNATURE_KEY));
		} catch (err) {
			return null;
		}
		return signature;
	}
}
