import { VirgilPublicKey } from '../VirgilPublicKey';
import { toArray } from '../utils/toArray';
import { validatePublicKeysArray } from '../validators';
import { VirgilStreamCipherBase } from './VirgilStreamCipherBase';

export class VirgilStreamCipher extends VirgilStreamCipherBase {
	constructor (publicKeys: VirgilPublicKey|VirgilPublicKey[]) {
		const publicKeyArr = toArray(publicKeys);
		validatePublicKeysArray(publicKeyArr);

		super();

		for (const { identifier, key} of publicKeyArr) {
			this.seqCipher.addKeyRecipientSafe(identifier, key);
		}

		const contentInfo = this.seqCipher.startEncryptionSafe();
		this.unshift(contentInfo);
	}
}
