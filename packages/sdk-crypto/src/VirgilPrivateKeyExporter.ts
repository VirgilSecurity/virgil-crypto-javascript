import { dataToUint8Array } from '@virgilsecurity/data-utils';

import { IPrivateKey, ICrypto, IPrivateKeyExporter, Data } from './types';

export class VirgilPrivateKeyExporter implements IPrivateKeyExporter {
  readonly virgilCrypto: ICrypto;

  constructor(virgilCrypto: ICrypto) {
    if (virgilCrypto == null) {
      throw new Error('`virgilCrypto` is required');
    }
    this.virgilCrypto = virgilCrypto;
  }

  exportPrivateKey(key: IPrivateKey) {
    return this.virgilCrypto.exportPrivateKey(key);
  }

  importPrivateKey(keyData: Data) {
    const myKeyData = dataToUint8Array(keyData, 'base64');
    return this.virgilCrypto.importPrivateKey(myKeyData);
  }
}
