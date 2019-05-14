import { WrappedVirgilSeqCipher } from '../common';
import { cryptoWrapper } from '../virgilCryptoWrapper';
import { Data } from '../interfaces';
import { anyToBuffer, StringEncoding } from '../utils/anyToBuffer';

/**
 * @internal
 *
 * Base class for `VirgilStreamCipher` and `VirgilStreamDecipher` wrapping
 * a low-level `VirgilSeqCipher` object.
 */
export class VirgilStreamCipherBase {
	/**
	 * Indicates whether the `final` method has been called.
	 */
	isFinished: boolean = false;

	/**
	 * Indicates whether the `dispose` method has been called.
	 * This can be `true` only in browser, because of the requirement to
	 * manually free the memory used by C++ class instances from virgil-crypto.
	 */
	private isDisposed: boolean = false;

	/**
	 * Instance of `VirgilSeqCipher` native class.
	 */
	protected seqCipher: WrappedVirgilSeqCipher;

	constructor () {
		this.seqCipher = cryptoWrapper.createVirgilSeqCipher();
	}

	/**
	 * Encrypt of decrypt chunk of data based on current mode.
	 * @param {Data} data - Chunk of data to encrypt \ decrypt
	 * @param {StringEncoding} encoding - If `data` is a string, specifies its
	 * encoding, otherwise is ignored. Default is 'utf8'.
	 *
	 * @returns {Buffer} - Encrypted or decrypted chunk
	 */
	update (data: Data, encoding: StringEncoding = 'utf8') {
		this.ensureLegalState();
		return this.seqCipher.processSafe(anyToBuffer(data, encoding));
	}

	/**
	 * Returns any remaining encrypted or decrypted data depending on current
	 * mode.
	 * Once `final` has been called, this instance cannot be used to encrypt
	 * or decrypt data, attempts to call any method including `final` will
	 * result in an error being thrown.
	 * This method also automatically calls `dispose`.
	 * @param {boolean} dispose - Optional. Indicating whether to automatically
	 * free the memory occupied by internal {@link seqSigner} object in the
	 * browser.
	 * Default is `true`. `false` is used to perform operations in inherited classes.
	 *
	 * In node.js this argument is ignored because the memory will be freed by the
	 * garbage collector.
	 */
	final (dispose: boolean = true) {
		this.ensureLegalState();
		try {
			return this.seqCipher.finishSafe();
		} finally {
			this.isFinished = true;
			if (dispose) this.dispose();
		}
	}

	/**
	 * Frees the memory occupied by {@link seqCipher} in the browser.
	 * In node.js this is a noop.
	 */
	dispose () {
		if (process.browser) {
			this.seqCipher.delete();
			this.isDisposed = true;
		}
	}

	/**
	 * @hidden
	 */
	protected ensureLegalState () {
		if (this.isFinished) {
			throw new Error('Illegal state. Cannot use cipher after the `final` method has been called.');
		}

		if (this.isDisposed) {
			throw new Error('Illegal state. Cannot use cipher after the `dispose` method has been called.');
		}
	}
}
