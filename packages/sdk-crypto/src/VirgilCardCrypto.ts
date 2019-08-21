import { dataToUint8Array } from '@virgilsecurity/data-utils';

import { IPrivateKey, IPublicKey, ICrypto, ICardCrypto, Data } from './types';

export class VirgilCardCrypto implements ICardCrypto {
  readonly virgilCrypto: ICrypto;

  constructor(virgilCrypto: ICrypto) {
    if (virgilCrypto == null) {
      throw new Error('`virgilCrypto` is required');
    }
    this.virgilCrypto = virgilCrypto;
  }

  generateSignature(data: Data, privateKey: IPrivateKey) {
    const myData = dataToUint8Array(data, 'utf8');
    return this.virgilCrypto.calculateSignature(myData, privateKey);
  }

  verifySignature(data: Data, signature: Data, publicKey: IPublicKey) {
    const myData = dataToUint8Array(data, 'utf8');
    const mySignature = dataToUint8Array(signature, 'base64');
    return this.virgilCrypto.verifySignature(myData, mySignature, publicKey);
  }

  exportPublicKey(publicKey: IPublicKey) {
    return this.virgilCrypto.exportPublicKey(publicKey);
  }

  importPublicKey(publicKeyData: Data) {
    const myPublicKeyData = dataToUint8Array(publicKeyData, 'base64');
    return this.virgilCrypto.importPublicKey(myPublicKeyData);
  }

  generateSha512(data: Data) {
    const myData = dataToUint8Array(data, 'utf8');
    return this.virgilCrypto.calculateHash(myData);
  }
}
