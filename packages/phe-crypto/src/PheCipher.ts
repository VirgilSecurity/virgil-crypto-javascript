import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPheModules } from './pheModules';
import { PheModules, Data, IPheCipher } from './types';

export class PheCipher implements IPheCipher {
  private pheModules: PheModules;
  private random: any;
  private pheCipher: any;

  constructor() {
    this.pheModules = getPheModules();
    this.random = new this.pheModules.CtrDrbg();
    this.pheCipher = new this.pheModules.PheCipher();
    this.pheCipher.random = this.random;
    this.pheCipher.setupDefaults();
  }

  encrypt(plainText: Data, accountKey: Data) {
    const myPlainText = dataToUint8Array(plainText, 'utf8');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const cipherText = this.pheCipher.encrypt(myPlainText, myAccountKey);
    return toBuffer(cipherText);
  }

  decrypt(cipherText: Data, accountKey: Data) {
    const myCipherText = dataToUint8Array(cipherText, 'base64');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const plainText = this.pheCipher.decrypt(myCipherText, myAccountKey);
    return toBuffer(plainText);
  }

  authEncrypt(plainText: Data, additionalData: Data, accountKey: Data) {
    const myPlainText = dataToUint8Array(plainText, 'utf8');
    const myAdditionalData = dataToUint8Array(additionalData, 'base64');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const cipherText = this.pheCipher.authEncrypt(myPlainText, myAdditionalData, myAccountKey);
    return toBuffer(cipherText);
  }

  authDecrypt(cipherText: Data, additionalData: Data, accountKey: Data) {
    const myCipherText = dataToUint8Array(cipherText, 'base64');
    const myAdditionalData = dataToUint8Array(additionalData, 'base64');
    const myAccountKey = dataToUint8Array(accountKey, 'base64');
    const plainText = this.pheCipher.authDecrypt(myCipherText, myAdditionalData, myAccountKey);
    return toBuffer(plainText);
  }
}
