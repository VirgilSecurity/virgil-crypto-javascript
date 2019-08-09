import {
  VirgilCrypto,
  IPrivateKey,
  IPublicKey,
  VirgilPrivateKey,
  VirgilPublicKey,
} from '@virgilsecurity/base-crypto';

import { prepareData } from './utils';

export class VirgilAccessTokenSigner {
  readonly virgilCrypto: VirgilCrypto;

  constructor(virgilCrypto: VirgilCrypto) {
    if (virgilCrypto == null) {
      throw new Error('`virgilCrypto` is required');
    }
    this.virgilCrypto = virgilCrypto;
  }

  getAlgorithm() {
    return 'VEDS512';
  }

  generateTokenSignature(token: Uint8Array | string, privateKey: IPrivateKey) {
    const myToken = prepareData(token, 'utf8');
    return this.virgilCrypto.calculateSignature(myToken, privateKey as VirgilPrivateKey);
  }

  verifyTokenSignature(
    token: Uint8Array | string,
    signature: Uint8Array | string,
    publicKey: IPublicKey,
  ) {
    const myToken = prepareData(token, 'utf8');
    const mySignature = prepareData(signature, 'base64');
    return this.virgilCrypto.verifySignature(myToken, mySignature, publicKey as VirgilPublicKey);
  }
};
