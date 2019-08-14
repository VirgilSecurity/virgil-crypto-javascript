import { Data, VirgilCrypto, VirgilPrivateKey, VirgilPublicKey } from '@virgilsecurity/base-crypto';

export class VirgilCardCrypto {
  readonly virgilCrypto: VirgilCrypto;

  constructor(virgilCrypto: VirgilCrypto) {
    if (virgilCrypto == null) {
      throw new Error('`virgilCrypto` is required');
    }
    this.virgilCrypto = virgilCrypto;
  }

  generateSignature(data: Data, privateKey: VirgilPrivateKey) {
    return this.virgilCrypto.calculateSignature(data, privateKey);
  }

  verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
    return this.virgilCrypto.verifySignature(data, signature, publicKey);
  }

  exportPublicKey(publicKey: VirgilPublicKey) {
    return this.virgilCrypto.exportPublicKey(publicKey);
  }

  importPublicKey(publicKeyData: Data) {
    return this.virgilCrypto.importPublicKey(publicKeyData);
  }

  generateSha512(data: Data) {
    return this.virgilCrypto.calculateHash(data, this.virgilCrypto.hashAlgorithm.SHA512);
  }
}
