import { VirgilCrypto, VirgilPrivateKey, VirgilPublicKey } from '@virgilsecurity/base-crypto';

import { Data } from './types';

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

  generateTokenSignature(token: Data, privateKey: VirgilPrivateKey) {
    return this.virgilCrypto.calculateSignature(token, privateKey);
  }

  verifyTokenSignature(token: Data, signature: Data, publicKey: VirgilPublicKey) {
    return this.virgilCrypto.verifySignature(token, signature, publicKey);
  }
};
