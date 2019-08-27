import { IPrivateKey, ICrypto, IPrivateKeyExporter, Data } from './types';

export class VirgilPrivateKeyExporter implements IPrivateKeyExporter {
  readonly crypto: ICrypto;

  constructor(crypto: ICrypto) {
    if (crypto == null) {
      throw new Error('`crypto` is required');
    }
    this.crypto = crypto;
  }

  exportPrivateKey(key: IPrivateKey) {
    return this.crypto.exportPrivateKey(key);
  }

  importPrivateKey(keyData: Data) {
    return this.crypto.importPrivateKey(keyData);
  }
}
