import { validatePrivateKey } from '../validators';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { getPrivateKeyBytes } from '../privateKeyUtils';
import { VirgilStreamSignerBase } from './VirgilStreamSignerBase';

/**
 * Class responsible for generating signatures of streams of data.
 */
export class VirgilStreamSigner extends VirgilStreamSignerBase {

	/**
	 * Initializes a new instance of `VirgilStreamSigner`.
	 * `VirgilStreamSigner` objects are not meant to be created with the `new`
	 * operator, use {@link VirgilCrypto.createStreamSigner} to create an instance.
	 *
	 * @internal
	 */
	constructor () {
		super();
		this.seqSigner.startSigningSafe();
	}

	/**
	 * Signs the data collected by {@link VirgilStreamSigner.update} method
	 * and returns the signature.
	 *
	 * @param {VirgilPrivateKey} privateKey - The private key to use to
	 * calculate the signature.
	 * @param {boolen} [final] - Optional. Indicating whether to automatically
	 * free the memory occupied by internal {@link seqSigner} object in the
	 * browser.
	 * Default is `true`. Pass `false` if you need to calculate more than one
	 * signature of the same data with different keys.
	 *
	 * In node.js this argument is ignored because the memory will be freed by the
	 * garbage collector.
	 *
	 * @returns {Buffer} The signature
	 */
	sign(privateKey: VirgilPrivateKey, final: boolean = true) {
		if (this.isDisposed()) {
			throw new Error(
				'Illegal state. The VirgilStreamSigner has been disposed. ' +
				'Pass `false` as the second argument to the `sign` method ' +
				'if you need to generate more than one signature.'
			);
		}

		validatePrivateKey(privateKey);
		const privateKeyValue = getPrivateKeyBytes(privateKey);

		try {
			return this.seqSigner.signSafe(privateKeyValue, Buffer.alloc(0));
		} finally {
			if (final) {
				this.dispose();
			}
		}
	}
}
