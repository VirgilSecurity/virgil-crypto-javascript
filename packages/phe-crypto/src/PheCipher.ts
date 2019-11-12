import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPheModules } from './pheModules';
import { PheModules, Data, IPheCipher } from './types';

export class PheCipher implements IPheCipher {
  private readonly pheModules: PheModules;
  private readonly pheCipher: any;

  private disposed: boolean;

  constructor() {
    this.pheModules = getPheModules();
    this.pheCipher = new this.pheModules.PheCipher();
    try {
      this.pheCipher.setupDefaults();
      this.disposed = false;
    } catch (error) {
      this.dispose();
      throw error;
    }
  }

  dispose() {
    this.pheCipher.delete();
    this.disposed = true;
  }

  encrypt(plainText: Data, accountKey: Data) {
    this.throwIfDisposed();
    const myPlainText = dataToUint8Array(plainText, 'utf8');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const cipherText = this.pheCipher.encrypt(myPlainText, myAccountKey);
    return toBuffer(cipherText);
  }

  decrypt(cipherText: Data, accountKey: Data) {
    this.throwIfDisposed();
    const myCipherText = dataToUint8Array(cipherText, 'base64');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const plainText = this.pheCipher.decrypt(myCipherText, myAccountKey);
    return toBuffer(plainText);
  }

  authEncrypt(plainText: Data, additionalData: Data, accountKey: Data) {
    this.throwIfDisposed();
    const myPlainText = dataToUint8Array(plainText, 'utf8');
    const myAdditionalData = dataToUint8Array(additionalData, 'base64');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const cipherText = this.pheCipher.authEncrypt(myPlainText, myAdditionalData, myAccountKey);
    return toBuffer(cipherText);
  }

  authDecrypt(cipherText: Data, additionalData: Data, accountKey: Data) {
    this.throwIfDisposed();
    const myCipherText = dataToUint8Array(cipherText, 'base64');
    const myAdditionalData = dataToUint8Array(additionalData, 'base64');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const plainText = this.pheCipher.authDecrypt(myCipherText, myAdditionalData, myAccountKey);
    return toBuffer(plainText);
  }

  private throwIfDisposed() {
    if (this.disposed) {
      throw new Error(
        'Cannot use an instance of `PheCipher` class after the `dispose` method has been called',
      );
    }
  }
}
