import { IVirgilCrypto, IPrivateKey, IPublicKey } from './IVirgilCrypto';
import { VirgilCrypto } from './VirgilCrypto';

export class VirgilAccessTokenSigner {
	private readonly crypto: IVirgilCrypto;

	constructor(virgilCrypto?: IVirgilCrypto) {
		this.crypto = virgilCrypto || new VirgilCrypto();
	}

	getAlgorithm() {
		return 'VEDS512';
	}

	generateTokenSignature (token: Buffer|string, privateKey: IPrivateKey) {
		return this.crypto.calculateSignature(token, privateKey);
	}

	verifyTokenSignature (token: Buffer|string, signature: Buffer|string, publicKey: IPublicKey) {
		return this.crypto.verifySignature(token, signature, publicKey);
	}
}
