import { validatePrivateKey } from '../validators';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { getPrivateKeyBytes } from '../privateKeyUtils';
import { VirgilStreamCipherBase } from './VirgilStreamCipherBase';

export class VirgilStreamDecipher extends VirgilStreamCipherBase {
	constructor (privateKey: VirgilPrivateKey) {
		validatePrivateKey(privateKey);

		super();

		const privateKeyValue = getPrivateKeyBytes(privateKey);
		this.seqCipher.startDecryptionWithKeySafe(
			privateKey.identifier,
			privateKeyValue,
			Buffer.alloc(0)
		);
	}
}
