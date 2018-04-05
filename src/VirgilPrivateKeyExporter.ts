import { IVirgilCrypto } from './IVirgilCrypto';
import { PrivateKey } from './createVirgilCrypto';

export class VirgilPrivateKeyExporter {
	public password?: string;
	private crypto: IVirgilCrypto;

	constructor(virgilCrypto: IVirgilCrypto, password?: string) {
		this.crypto = virgilCrypto;
		this.password = password;
	}

	exportPrivateKey = (key: PrivateKey) => this.crypto.exportPrivateKey(key, this.password);

	importPrivateKey = (keyData: Buffer|string) => this.crypto.importPrivateKey(keyData);
}
