import { VirgilCryptoType, IPrivateKey, VirgilPrivateKey } from '@virgilsecurity/base-crypto';

import { prepareData } from './utils';

export class VirgilPrivateKeyExporter {
  readonly virgilCrypto: VirgilCryptoType;

  constructor(virgilCrypto: VirgilCryptoType) {
    if (virgilCrypto == null) {
      throw new Error('`virgilCrypto` is required');
    }
    this.virgilCrypto = virgilCrypto;
  }

  exportPrivateKey(key: IPrivateKey) {
    return this.virgilCrypto.exportPrivateKey(key as VirgilPrivateKey);
  }

  importPrivateKey(keyData: Uint8Array | string) {
    const myKeyData = prepareData(keyData, 'utf8');
    return this.virgilCrypto.importPrivateKey(myKeyData);
  }
}
