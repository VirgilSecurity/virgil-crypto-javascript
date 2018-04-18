import { IVirgilCrypto, IPrivateKey, IPublicKey,  } from './IVirgilCrypto';
import { HashAlgorithm } from './common';
import { VirgilCrypto } from './VirgilCrypto';

export class VirgilCardCrypto {
	private readonly crypto: IVirgilCrypto;

	constructor(virgilCrypto?: IVirgilCrypto) {
		this.crypto = virgilCrypto || new VirgilCrypto();
	}

	generateSignature (data: Buffer|string, privateKey: IPrivateKey) {
		return this.crypto.calculateSignature(data, privateKey);
	}

	verifySignature (data: Buffer|string, signature: Buffer|string, publicKey: IPublicKey) {
		return this.crypto.verifySignature(data, signature, publicKey);
	}

	exportPublicKey (publicKey: IPublicKey) {
		return this.crypto.exportPublicKey(publicKey);
	}

	importPublicKey (publicKeyData: Buffer|string) {
		return this.crypto.importPublicKey(publicKeyData) as IPublicKey;
	}

	generateSha512 (data: Buffer|string) {
		return this.crypto.calculateHash(data, HashAlgorithm.SHA512);
	}
}
