import { IVirgilCrypto } from './IVirgilCrypto';
import { PrivateKey, PublicKey } from './createVirgilCrypto';

type Data = Buffer|string;

export class VirgilAccessTokenSigner {
	private crypto: IVirgilCrypto;

	constructor(virgilCrypto: IVirgilCrypto) {
		this.crypto = virgilCrypto;
	}

	getAlgorithm() {
		return 'VEDS512';
	}

	generateTokenSignature = (token: Data, privateKey: PrivateKey) =>
		this.crypto.calculateSignature(token, privateKey);

	verifyTokenSignature = (token: Data, signature: Data, publicKey: PublicKey) =>
		this.crypto.verifySignature(token, signature, publicKey);
}
