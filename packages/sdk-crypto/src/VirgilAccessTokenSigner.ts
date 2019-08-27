import { IPrivateKey, IPublicKey, ICrypto, IAccessTokenSigner, Data } from './types';

export class VirgilAccessTokenSigner implements IAccessTokenSigner {
  readonly crypto: ICrypto;

  constructor(crypto: ICrypto) {
    if (crypto == null) {
      throw new Error('`crypto` is required');
    }
    this.crypto = crypto;
  }

  getAlgorithm() {
    return 'VEDS512';
  }

  generateTokenSignature(token: Data, privateKey: IPrivateKey) {
    return this.crypto.calculateSignature(token, privateKey);
  }

  verifyTokenSignature(token: Data, signature: Data, publicKey: IPublicKey) {
    return this.crypto.verifySignature(token, signature, publicKey);
  }
};
