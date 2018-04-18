import { IVirgilCrypto, IPrivateKey, IPublicKey,  } from './IVirgilCrypto';
import { HashAlgorithm } from './common';
import { VirgilCrypto } from './VirgilCrypto';

type Data = Buffer|string;

export class VirgilCardCrypto {
	private readonly crypto: IVirgilCrypto;

	constructor(virgilCrypto: IVirgilCrypto) {
		this.crypto = virgilCrypto || new VirgilCrypto();
	}

	generateSignature = (data: Data, privateKey: IPrivateKey) => this.crypto.calculateSignature(data, privateKey);

	verifySignature = (data: Data, signature: Data, publicKey: IPublicKey) =>
		this.crypto.verifySignature(data, signature, publicKey);

	exportPublicKey = (publicKey: IPublicKey) => this.crypto.exportPublicKey(publicKey);

	importPublicKey = (publicKeyData: Data) => this.crypto.importPublicKey(publicKeyData) as IPublicKey;

	generateSha512 = (data: Data) => this.crypto.calculateHash(data, HashAlgorithm.SHA512);
}
