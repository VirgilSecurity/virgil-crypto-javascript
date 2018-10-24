import { WrappedVirgilSeqSigner } from '../common';
import { cryptoWrapper } from '../virgilCryptoWrapper';

export class VirgilStreamSignerBase {
	// tslint:disable-next-line:variable-name
	private _isDisposed: boolean = false;
	protected seqSigner: WrappedVirgilSeqSigner

	constructor() {
		this.seqSigner = cryptoWrapper.createVirgilSeqSigner();
	}

	update(data: Buffer) {
		if (this.isDisposed()) {
			throw new Error('Illegal state. Cannot use signer after the `dispose` method has been called.');
		}

		this.seqSigner.updateSafe(data);
		return this;
	}

	dispose() {
		if (process.browser) {
			this.seqSigner.delete();
			this._isDisposed = true;
		}
	}

	protected isDisposed() {
		return this._isDisposed;
	}
}
