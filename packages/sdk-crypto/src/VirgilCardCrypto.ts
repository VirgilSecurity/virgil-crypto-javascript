import {
  VirgilCrypto,
  IPrivateKey,
  IPublicKey,
  VirgilPrivateKey,
  VirgilPublicKey,
} from '@virgilsecurity/base-crypto';

import { prepareData } from './utils';

export class VirgilCardCrypto {
  readonly virgilCrypto: VirgilCrypto;

  constructor(virgilCrypto: VirgilCrypto) {
    if (virgilCrypto == null) {
      throw new Error('`virgilCrypto` is required');
    }
    this.virgilCrypto = virgilCrypto;
  }

  generateSignature(data: Uint8Array | string, privateKey: IPrivateKey) {
    const myData = prepareData(data, 'utf8');
    return this.virgilCrypto.calculateSignature(myData, privateKey as VirgilPrivateKey);
  }

  verifySignature(
    data: Uint8Array | string,
    signature: Uint8Array | string,
    publicKey: IPublicKey,
  ) {
    const myData = prepareData(data, 'utf8');
    const mySignature = prepareData(signature, 'base64');
    return this.virgilCrypto.verifySignature(myData, mySignature, publicKey as VirgilPublicKey);
  }

  exportPublicKey(publicKey: IPublicKey) {
    return this.virgilCrypto.exportPublicKey(publicKey as VirgilPublicKey);
  }

  importPublicKey(publicKeyData: Uint8Array | string) {
    const myPublicKeyData = prepareData(publicKeyData, 'base64');
    return this.virgilCrypto.importPublicKey(myPublicKeyData);
  }

  generateSha512(data: Uint8Array | string) {
    const myData = prepareData(data, 'utf8');
    return this.virgilCrypto.calculateHash(myData, this.virgilCrypto.hashAlgorithm.SHA512);
  }
}
