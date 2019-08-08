import { DATA_SIGNATURE_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { getLowLevelPrivateKey } from './privateKeyUtils';
import { Data } from './types';
import { dataToUint8Array, toBuffer } from './utils';
import { validatePrivateKey } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';

export class VirgilStreamDecipher {
  isFinished = false;

  private isDisposed = false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private recipientCipher: any;

  constructor(privateKey: VirgilPrivateKey) {
    const foundationModules = getFoundationModules();

    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    this.recipientCipher = new foundationModules.RecipientCipher();

    this.recipientCipher.startDecryptionWithKey(
      privateKey.identifier,
      lowLevelPrivateKey,
      new Uint8Array(0),
    );
  }

  getSignature() {
    if (!this.isFinished) {
      throw new Error(
        'Illegal state. Cannot get signature before the `final` method has been called.',
      );
    }
    if (this.isDisposed) {
      throw new Error(
        'Illegal state. Cannot get signature after the `dispose` method has been called.',
      );
    }
    const messageInfoCustomParams = this.recipientCipher.customParams();
    try {
      return toBuffer(messageInfoCustomParams.findData(DATA_SIGNATURE_KEY));
    } finally {
      messageInfoCustomParams.delete();
    }
  }

  update(data: Data) {
    this.ensureLegalState();
    const myData = dataToUint8Array(data);
    return toBuffer(this.recipientCipher.processDecryption(myData));
  }

  final(dispose: boolean = true) {
    this.ensureLegalState();
    try {
      return toBuffer(this.recipientCipher.finishDecryption());
    } finally {
      this.isFinished = true;
      if (dispose) {
        this.dispose();
      }
    }
  }

  dispose() {
    this.recipientCipher.delete();
    this.isDisposed = true;
  }

  private ensureLegalState() {
    if (this.isFinished) {
      throw new Error('Illegal state. Cannot use cipher after the `final` method has been called.');
    }
    if (this.isDisposed) {
      throw new Error(
        'Illegal state. Cannot use cipher after the `dispose` method has been called.',
      );
    }
  }
}
