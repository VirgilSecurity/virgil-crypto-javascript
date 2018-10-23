import { WrappedVirgilSeqCipher } from '../common';
import { cryptoWrapper } from '../virgilCryptoWrapper';
import { Data } from '../interfaces';
import { anyToBuffer, StringEncoding } from '../utils/anyToBuffer';

export class VirgilStreamCipherBase {
	private isFinished: boolean = false;
	private isDisposed: boolean = false;

	protected seqCipher: WrappedVirgilSeqCipher;

	constructor () {
		this.seqCipher = cryptoWrapper.createVirgilSeqCipher();
	}

	update (data: Data, encoding: StringEncoding = 'utf8') {
		this.ensureLegalState();
		return this.seqCipher.processSafe(anyToBuffer(data, encoding));
	}

	final (data?: Data, encoding: StringEncoding = 'utf8') {
		this.ensureLegalState();

		try {
			if (data) {
				const lastProcessed = this.seqCipher.processSafe(anyToBuffer(data, encoding));
				const final = this.seqCipher.finishSafe();
				return Buffer.concat([ lastProcessed, final ]);
			}
			return this.seqCipher.finishSafe();
		} finally {
			this.isFinished = true;
			this.dispose();
		}
	}

	dispose () {
		if (process.browser) {
			this.seqCipher.delete();
			this.isDisposed = true;
		}
	}

	protected ensureLegalState () {
		if (this.isFinished) {
			throw new Error('Illegal state. Cannot use cipher after the `final` method has been called.');
		}

		if (this.isDisposed) {
			throw new Error('Illegal state. Cannot use cipher after the `dispose` method has been called.');
		}
	}
}
