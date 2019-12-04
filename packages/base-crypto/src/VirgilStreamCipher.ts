import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { DATA_SIGNATURE_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { Data } from './types';
import { toArray } from './utils';
import { validatePublicKeysArray } from './validators';
import { VirgilPublicKey } from './VirgilPublicKey';

export class VirgilStreamCipher {
  private _isFinished = false;
  private isRunning = false;
  private isDisposed = false;
  private recipientCipher: FoundationModules.RecipientCipher;
  private messageInfoCustomParams?: FoundationModules.MessageInfoCustomParams;
  private aes256Gcm: FoundationModules.Aes256Gcm;
  private ctrDrbg: FoundationModules.CtrDrbg;
  private publicKeys: VirgilPublicKey[];

  get isFinished() {
    return this._isFinished;
  }

  constructor(publicKey: VirgilPublicKey | VirgilPublicKey[], signature?: Data) {
    const foundationModules = getFoundationModules();

    this.publicKeys = toArray(publicKey);
    validatePublicKeysArray(this.publicKeys);

    this.ctrDrbg = new foundationModules.CtrDrbg();
    try {
      this.ctrDrbg.setupDefaults();
    } catch (error) {
      this.ctrDrbg.delete();
      throw error;
    }

    this.recipientCipher = new foundationModules.RecipientCipher();
    this.aes256Gcm = new foundationModules.Aes256Gcm();
    this.recipientCipher.encryptionCipher = this.aes256Gcm;
    this.recipientCipher.random = this.ctrDrbg;

    this.publicKeys.forEach(({ identifier }, index) => {
      this.recipientCipher.addKeyRecipient(identifier, this.publicKeys[index].lowLevelPublicKey);
    });

    if (signature) {
      const mySignature = dataToUint8Array(signature, 'base64');
      this.messageInfoCustomParams = this.recipientCipher.customParams();
      this.messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, mySignature);
    }
  }

  start() {
    this.ensureLegalState();
    this.recipientCipher.startEncryption();
    this.isRunning = true;
    return toBuffer(this.recipientCipher.packMessageInfo());
  }

  update(data: Data) {
    this.ensureLegalState();
    this.ensureIsRunning();
    const myData = dataToUint8Array(data, 'utf8');
    return toBuffer(this.recipientCipher.processEncryption(myData));
  }

  final(dispose = true) {
    this.ensureLegalState();
    this.ensureIsRunning();
    try {
      return toBuffer(this.recipientCipher.finishEncryption());
    } finally {
      this._isFinished = true;
      this.isRunning = false;
      if (dispose) {
        this.dispose();
      }
    }
  }

  dispose() {
    this.recipientCipher.delete();
    this.aes256Gcm.delete();
    this.ctrDrbg.delete();
    if (this.messageInfoCustomParams) {
      this.messageInfoCustomParams.delete();
    }
    this.isDisposed = true;
  }

  private ensureLegalState() {
    if (this._isFinished) {
      throw new Error('Illegal state. Cannot use cipher after the `final` method has been called.');
    }
    if (this.isDisposed) {
      throw new Error(
        'Illegal state. Cannot use cipher after the `dispose` method has been called.',
      );
    }
  }

  private ensureIsRunning() {
    if (!this.isRunning) {
      throw new Error('Illegal state. Cannot use cipher before the `start` method.');
    }
  }
}
