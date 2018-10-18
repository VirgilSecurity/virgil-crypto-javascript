import { VirgilPublicKey } from '../VirgilPublicKey';
import { validatePublicKey } from '../validators';
import { anyToBuffer, StringEncoding } from '../utils/anyToBuffer';
import { Data } from '../interfaces';
import { VirgilStreamSignerBase } from './VirgilStreamSignerBase';

export class VirgilStreamVerifier extends VirgilStreamSignerBase {

	constructor(signature: Data, encoding: StringEncoding = 'base64') {
		super();
		this.seqSigner.startVerifyingSafe(anyToBuffer(signature, encoding));
	}

	verify(publicKey: VirgilPublicKey, final: boolean = true) {
		if (this.isDisposed()) {
			throw new Error(
				'The VirgilStreamVerifier has been disposed. ' +
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
