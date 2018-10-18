import { Transform, TransformCallback } from 'stream';
import { WrappedVirgilSeqCipher } from '../common';
import { cryptoWrapper } from '../virgilCryptoWrapper';

export class VirgilStreamCipherBase extends Transform {
	protected seqCipher: WrappedVirgilSeqCipher

	constructor () {
		super();
		this.seqCipher = cryptoWrapper.createVirgilSeqCipher();
	}

	// tslint:disable-next-line:function-name
	_flush (callback: TransformCallback) {
		try {
			this.push(this.seqCipher.finishSafe());
		} catch (err) {
			callback(err);
			return;
		} finally {
			this.dispose();
		}
		callback();
	}

	// tslint:disable-next-line:function-name
	_destroy () {
		this.dispose();
	}

	// tslint:disable-next-line:function-name
	_transform(chunk: any, encoding: string, callback: TransformCallback) {
		try {
			this.push(this.seqCipher.processSafe(chunk));
		} catch (err) {
			callback(err);
		}

		callback();
	}

	dispose () {
		if (process.browser) {
			this.seqCipher.delete();
		}
	}
}
