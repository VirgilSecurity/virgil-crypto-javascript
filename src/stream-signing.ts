import { Transform } from 'stream';
import { VirgilPublicKey } from './VirgilPublicKey';
import { validatePrivateKey, validatePublicKey } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { getPrivateKeyBytes } from './privateKeyUtils';
import { cryptoWrapper } from './virgilCryptoWrapper';
import { anyToBuffer, StringEncoding } from './utils/anyToBuffer';
import { Data } from './interfaces';

class VirgilSeqSignerWrapper extends Transform {
	protected seqSigner: any;

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
		if (process.browser) {
			this.seqSigner.delete();
		}
	}

	update(data: Buffer) {
		this.seqSigner.updateSafe(data);
		return this;
	}

	dispose() {
		if (process.browser) {
			this.seqSigner.delete();
		}
	}
}

export class VirgilStreamSigner extends VirgilSeqSignerWrapper {
	constructor() {
		super();
		this.seqSigner.startSigningSafe();
	}

	sign(privateKey: VirgilPrivateKey, final: boolean = true) {
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

export class VirgilStreamVerifier extends VirgilSeqSignerWrapper {
	constructor(signature: Data, encoding: StringEncoding = 'base64') {
		super();
		this.seqSigner.startVerifyingSafe(anyToBuffer(signature, encoding));
	}

	verify(publicKey: VirgilPublicKey, final: boolean = true) {
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
