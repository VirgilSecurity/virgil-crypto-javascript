import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { DATA_SIGNATURE_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { getRandom } from './globalInstances';
import { Data } from './types';
import { toArray } from './utils';
import { validatePublicKeysArray } from './validators';
import { VirgilCryptoErrorStatus, VirgilCryptoError } from './VirgilCryptoError';
import { VirgilPublicKey } from './VirgilPublicKey';

export class VirgilStreamCipher {
  private _isFinished: boolean;
  private _isRunning: boolean;
  private _isDisposed: boolean;

  private readonly recipientCipher: FoundationModules.RecipientCipher;
  private readonly messageInfoCustomParams?: FoundationModules.MessageInfoCustomParams;
  private readonly aes256Gcm: FoundationModules.Aes256Gcm;

  get isRunning() {
    return this._isRunning;
  }

  get isFinished() {
    return this._isFinished;
  }

  get isDisposed() {
    return this._isDisposed;
  }

  constructor(arg0: VirgilPublicKey | VirgilPublicKey[], arg1?: Data) {
    const foundationModules = getFoundationModules();
    const publicKeys = toArray(arg0);
    validatePublicKeysArray(publicKeys);
    this.recipientCipher = new foundationModules.RecipientCipher();
    this.aes256Gcm = new foundationModules.Aes256Gcm();
    this.recipientCipher.encryptionCipher = this.aes256Gcm;
    this.recipientCipher.random = getRandom();
    publicKeys.forEach(publicKey => {
      this.recipientCipher.addKeyRecipient(publicKey.identifier, publicKey.lowLevelPublicKey);
    });
    if (arg1) {
      const mySignature = dataToUint8Array(arg1, 'base64');
      this.messageInfoCustomParams = this.recipientCipher.customParams();
      this.messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, mySignature);
    }
    this._isFinished = false;
    this._isRunning = false;
    this._isDisposed = false;
  }

  start() {
    this.ensureLegalState();
    this.recipientCipher.startEncryption();
    this._isRunning = true;
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
      this._isRunning = false;
      if (dispose) {
        this.dispose();
      }
    }
  }

  dispose() {
    if (this.messageInfoCustomParams) {
      this.messageInfoCustomParams.delete();
    }
    this.aes256Gcm.delete();
    this.recipientCipher.delete();
    this._isDisposed = true;
  }

  private ensureLegalState() {
    if (this._isDisposed) {
      throw new VirgilCryptoError(
        VirgilCryptoErrorStatus.STREAM_ILLEGAL_STATE,
        "Illegal state. Cannot use cipher after the 'dispose' method has been called.",
      );
    }
    if (this._isFinished) {
      throw new VirgilCryptoError(
        VirgilCryptoErrorStatus.STREAM_ILLEGAL_STATE,
        "Illegal state. Cannot use cipher after the 'final' method has been called.",
      );
    }
  }

  private ensureIsRunning() {
    if (!this._isRunning) {
      throw new VirgilCryptoError(
        VirgilCryptoErrorStatus.STREAM_ILLEGAL_STATE,
        "Illegal state. Cannot use cipher before the 'start' method.",
      );
    }
  }
}
