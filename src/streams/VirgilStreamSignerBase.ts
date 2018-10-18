import { Transform } from 'stream';
import { WrappedVirgilSeqSigner } from '../common';
import { cryptoWrapper } from '../virgilCryptoWrapper';

export class VirgilStreamSignerBase extends Transform {

	// tslint:disable-next-line:variable-name
	private _isDisposed: boolean = false;
	protected seqSigner: WrappedVirgilSeqSigner

	constructor() {
		super();
		this.seqSigner = cryptoWrapper.createVirgilSeqSigner();
	}

	// tslint:disable-next-line:function-name
	_transform(chunk: Buffer, encoding: string, callback: Function) {
		this.seqSigner.updateSafe(chunk);
		callback(null, chunk);
	}

	// tslint:disable-next-line:function-name
	_destroy () {
		this.dispose();
	}

	update(data: Buffer) {
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
