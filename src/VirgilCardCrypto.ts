import { IVirgilCrypto } from './IVirgilCrypto';
import { PrivateKey, PublicKey } from './createVirgilCrypto';
import { HashAlgorithm } from './common';

type Data = Buffer|string;

export class VirgilCardCrypto {
	private crypto: IVirgilCrypto;

	constructor(virgilCrypto: IVirgilCrypto) {
		this.crypto = virgilCrypto;
	}

	generateSignature = (data: Data, privateKey: PrivateKey) => this.crypto.calculateSignature(data, privateKey);

	verifySignature = (data: Data, signature: Data, publicKey: PublicKey) =>
		this.crypto.verifySignature(data, signature, publicKey);

	exportPublicKey = (publicKey: PublicKey) => this.crypto.exportPublicKey(publicKey);

	importPublicKey = (publicKeyData: Data) => this.crypto.importPublicKey(publicKeyData);

	generateSha512 = (data: Data) => this.crypto.calculateHash(data, HashAlgorithm.SHA512);
}
