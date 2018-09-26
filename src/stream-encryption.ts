import { Transform, TransformCallback } from 'stream';
import { VirgilPublicKey } from './VirgilPublicKey';
import { toArray } from './utils/toArray';
import { validatePublicKeysArray, validatePrivateKey } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { getPrivateKeyBytes } from './privateKeyUtils';
import { WrappedVirgilSeqCipher } from './common';

class VirgilSeqCipherWrapper extends Transform {

	constructor (protected seqCipher: WrappedVirgilSeqCipher) {
		super();
	}

	// tslint:disable-next-line:function-name
	_flush (callback: TransformCallback) {
		try {
			this.push(this.seqCipher.finishSafe());
		} catch (err) {
			callback(err);
			return;
		} finally {
			if (process.browser) {
				this.seqCipher.delete();
			}
		}
		callback();
	}

	// tslint:disable-next-line:function-name
	_destroy () {
		if (process.browser) {
			this.seqCipher.delete();
		}
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
}

export class VirgilStreamCipher extends VirgilSeqCipherWrapper {
	constructor (seqCipher: WrappedVirgilSeqCipher, publicKeys: VirgilPublicKey|VirgilPublicKey[]) {
		const publicKeyArr = toArray(publicKeys);
		validatePublicKeysArray(publicKeyArr);

		super(seqCipher);

		for (const { identifier, key} of publicKeyArr) {
			this.seqCipher.addKeyRecipientSafe(identifier, key);
		}

		const contentInfo = this.seqCipher.startEncryptionSafe();
		this.unshift(contentInfo);
	}
}

export class VirgilStreamDecipher extends VirgilSeqCipherWrapper {
	constructor (seqCipher: WrappedVirgilSeqCipher, privateKey: VirgilPrivateKey) {
		validatePrivateKey(privateKey);

		super(seqCipher);

		const privateKeyValue = getPrivateKeyBytes(privateKey);
		seqCipher.startDecryptionWithKeySafe(
			privateKey.identifier,
			privateKeyValue,
			Buffer.alloc(0)
		);
	}
}
