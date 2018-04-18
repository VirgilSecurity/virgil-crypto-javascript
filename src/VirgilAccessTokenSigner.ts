import { IVirgilCrypto, IPrivateKey, IPublicKey } from './IVirgilCrypto';
import { VirgilCrypto } from './VirgilCrypto';

type Data = Buffer|string;

export class VirgilAccessTokenSigner {
	private readonly crypto: IVirgilCrypto;

	constructor(virgilCrypto?: IVirgilCrypto) {
		this.crypto = virgilCrypto || new VirgilCrypto();
	}

	getAlgorithm() {
		return 'VEDS512';
	}

	generateTokenSignature = (token: Data, privateKey: IPrivateKey) =>
		this.crypto.calculateSignature(token, privateKey);

	verifyTokenSignature = (token: Data, signature: Data, publicKey: IPublicKey) =>
		this.crypto.verifySignature(token, signature, publicKey);
}
