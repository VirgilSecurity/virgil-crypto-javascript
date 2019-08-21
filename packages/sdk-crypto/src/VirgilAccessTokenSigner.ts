import { dataToUint8Array } from '@virgilsecurity/data-utils';

import { IPrivateKey, IPublicKey, ICrypto, IAccessTokenSigner, Data } from './types';

export class VirgilAccessTokenSigner implements IAccessTokenSigner {
  readonly virgilCrypto: ICrypto;

  constructor(virgilCrypto: ICrypto) {
    if (virgilCrypto == null) {
      throw new Error('`virgilCrypto` is required');
    }
    this.virgilCrypto = virgilCrypto;
  }

  getAlgorithm() {
    return 'VEDS512';
  }

  generateTokenSignature(token: Data, privateKey: IPrivateKey) {
    const myToken = dataToUint8Array(token, 'utf8');
    return this.virgilCrypto.calculateSignature(myToken, privateKey);
  }

  verifyTokenSignature(token: Data, signature: Data, publicKey: IPublicKey) {
    const myToken = dataToUint8Array(token, 'utf8');
    const mySignature = dataToUint8Array(signature, 'base64');
    return this.virgilCrypto.verifySignature(myToken, mySignature, publicKey);
  }
};
