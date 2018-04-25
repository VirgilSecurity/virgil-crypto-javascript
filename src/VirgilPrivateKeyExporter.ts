import { IVirgilCrypto, IPrivateKey } from './IVirgilCrypto';
import { VirgilCrypto } from './VirgilCrypto';

export class VirgilPrivateKeyExporter {
	public password?: string;
	private readonly crypto: IVirgilCrypto;

	constructor(virgilCrypto?: IVirgilCrypto, password?: string) {
		if (typeof virgilCrypto === 'string' && typeof password === 'undefined') {
			password = virgilCrypto;
			virgilCrypto = undefined;
		}

		this.crypto = virgilCrypto || new VirgilCrypto();
		this.password = password;
	}

	exportPrivateKey (key: IPrivateKey) {
		return this.crypto.exportPrivateKey(key, this.password);
	}

	importPrivateKey (keyData: Buffer|string) {
		return this.crypto.importPrivateKey(keyData) as IPrivateKey;
	}
}
