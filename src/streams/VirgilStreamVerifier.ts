import { VirgilPublicKey } from '../VirgilPublicKey';
import { validatePublicKey } from '../validators';
import { anyToBuffer, StringEncoding } from '../utils/anyToBuffer';
import { Data } from '../interfaces';
import { VirgilStreamSignerBase } from './VirgilStreamSignerBase';

/**
 * Class responsible for verifying signatures of streams of data.
 */
export class VirgilStreamVerifier extends VirgilStreamSignerBase {

	/**
	 * Initializes a new instance of `VirgilStreamVerifier`.
	 * `VirgilStreamVerifier` objects are not meant to be created with the `new`
	 * operator, use {@link VirgilCrypto.createStreamVerifier} to create an instance.
	 *
	 * @internal
	 *
	 * @param {Data} signature = The signature to be verified.
	 * @param {StringEncoding} [encoding] - If `signature` is a string,
	 * specifies its encoding, otherwise is ignored. Default is 'utf8'.
	 */
	constructor(signature: Data, encoding: StringEncoding = 'base64') {
		const signatureBuf = anyToBuffer(signature, encoding, 'signature');
		super();
		this.seqSigner.startVerifyingSafe(signatureBuf);
	}

	/**
	 * Verifies the validity of the signature for the data collected by the
	 * {@link VirgilStreamVerifier.update} method and the given public key.
	 *
	 * @param {VirgilPublicKey} publicKey - The public key to use to verify
	 * the signature.
	 * @param {boolean} [final] - Optional. Indicating whether to automatically
	 * free the memory occupied by internal {@link seqSigner} object in the
	 * browser.
	 * Default is `true`. Pass `false` if you need to verify the signature
	 * with more than one public key.
	 *
	 * In node.js this argument is ignored because the memory will be freed by the
	 * garbage collector.
	 *
	 * @returns {boolean} `true` if signature is valid, otherwise `false`
	 */
	verify(publicKey: VirgilPublicKey, final: boolean = true) {
		if (this.isDisposed()) {
			throw new Error(
				'Illegal state. The VirgilStreamVerifier has been disposed. ' +
				'Pass `false` as the second argument to the `verify` method ' +
				'if you need to verify with more than one public key.'
			);
		}

		validatePublicKey(publicKey);

		try {
			return this.seqSigner.verifySafe(publicKey.key);
		} finally {
			if (final) {
				this.dispose();
			}
		}
	}
}
