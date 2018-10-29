import { WrappedVirgilSeqSigner } from '../common';
import { cryptoWrapper } from '../virgilCryptoWrapper';
import { Data } from '../interfaces';
import { anyToBuffer, StringEncoding } from '../utils/anyToBuffer';

/**
 * @internal
 * Base class for `VirgilStreamSigner` and `VirgilStreamVerifier` wrapping
 * a low-level `VirgilSeqSigner` object.
 */
export class VirgilStreamSignerBase {
	/**
	 * Inidcates whether the `dispose` method has been called.
	 */
	// tslint:disable-next-line:variable-name
	private _isDisposed: boolean = false;

	/**
	 * Instance of `VirgilSeqSigner` native class.
	 */
	protected seqSigner: WrappedVirgilSeqSigner

	constructor() {
		this.seqSigner = cryptoWrapper.createVirgilSeqSigner();
	}

	/**
	 * Add new chunk of data to be signed or verified.
	 * @param {Data} data - The chunk of data to be signed or verified.
	 * @param {StringEncoding} [encoding] - If `data` is a string, specifies it's
	 * encoding, otherwise is ignored. Default is 'utf8'.
	 */
	update(data: Data, encoding: StringEncoding = 'utf8') {
		if (this.isDisposed()) {
			throw new Error('Illegal state. Cannot use signer after the `dispose` method has been called.');
		}

		this.seqSigner.updateSafe(anyToBuffer(data, encoding));
		return this;
	}

	/**
	 * Frees the memory occupied by {@link seqSigner} in the browser.
	 * In node.js this is a noop.
	 */
	dispose() {
		if (process.browser) {
			this.seqSigner.delete();
			this._isDisposed = true;
		}
	}

	/**
	 * @hidden
	 */
	protected isDisposed() {
		return this._isDisposed;
	}
}
