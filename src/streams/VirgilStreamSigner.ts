import { validatePrivateKey } from '../validators';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { getPrivateKeyBytes } from '../privateKeyUtils';
import { VirgilStreamSignerBase } from './VirgilStreamSignerBase';

export class VirgilStreamSigner extends VirgilStreamSignerBase {

	constructor () {
		super();
		this.seqSigner.startSigningSafe();
	}

	sign(privateKey: VirgilPrivateKey, final: boolean = true) {
		if (this.isDisposed()) {
			throw new Error(
				'The VirgilStreamSigner has been disposed. ' +
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
