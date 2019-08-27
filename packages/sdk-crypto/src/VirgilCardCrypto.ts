import { IPrivateKey, IPublicKey, ICrypto, ICardCrypto, Data } from './types';

export class VirgilCardCrypto implements ICardCrypto {
  readonly crypto: ICrypto;

  constructor(crypto: ICrypto) {
    if (crypto == null) {
      throw new Error('`crypto` is required');
    }
    this.crypto = crypto;
  }

  generateSignature(data: Data, privateKey: IPrivateKey) {
    return this.crypto.calculateSignature(data, privateKey);
  }

  verifySignature(data: Data, signature: Data, publicKey: IPublicKey) {
    return this.crypto.verifySignature(data, signature, publicKey);
  }

  exportPublicKey(publicKey: IPublicKey) {
    return this.crypto.exportPublicKey(publicKey);
  }

  importPublicKey(publicKeyData: Data) {
    return this.crypto.importPublicKey(publicKeyData);
  }

  generateSha512(data: Data) {
    return this.crypto.calculateHash(data);
  }
}
