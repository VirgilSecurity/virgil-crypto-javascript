import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { PADDING_LEN } from './constants';
import { getFoundationModules } from './foundationModules';
import { getRandom } from './globalInstances';
import { FoundationModules, Data } from './types';
import { toArray } from './utils';
import { validatePrivateKey, validatePublicKeysArray } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export class VirgilStreamSignAndEncrypt {
  private _isRunning: boolean;
  private _isFinished: boolean;
  private _isDisposed: boolean;

  private readonly recipientCipher: FoundationModules.RecipientCipher;
  private readonly aes256Gcm: FoundationModules.Aes256Gcm;
  private readonly sha512: FoundationModules.Sha512;
  private readonly randomPadding: FoundationModules.RandomPadding | undefined;
  private readonly paddingParams: FoundationModules.PaddingParams | undefined;

  get isRunning() {
    return this._isRunning;
  }

  get isFinished() {
    return this._isFinished;
  }

  get isDisposed() {
    return this._isDisposed;
  }

  // TODO: This doesn't work :(
  // constructor(privateKey: VirgilPrivateKey, publicKey: VirgilPublicKey, enablePadding?: boolean);
  // constructor(privateKey: VirgilPrivateKey, publicKeys: VirgilPublicKey[], enablePadding?: boolean);
  constructor(arg0: VirgilPrivateKey, arg1: VirgilPublicKey | VirgilPublicKey[], arg2?: boolean) {
    validatePrivateKey(arg0);
    const publicKeys = toArray(arg1);
    validatePublicKeysArray(publicKeys);
    const foundation = getFoundationModules();
    const random = getRandom();
    this.recipientCipher = new foundation.RecipientCipher();
    this.aes256Gcm = new foundation.Aes256Gcm();
    this.sha512 = new foundation.Sha512();
    this.recipientCipher.encryptionCipher = this.aes256Gcm;
    this.recipientCipher.random = random;
    this.recipientCipher.signerHash = this.sha512;
    if (arg2) {
      this.randomPadding = new foundation.RandomPadding();
      this.randomPadding.random = random;
      this.recipientCipher.encryptionPadding = this.randomPadding;
      this.paddingParams = foundation.PaddingParams.newWithConstraints(PADDING_LEN, PADDING_LEN);
      this.recipientCipher.paddingParams = this.paddingParams;
    }
    publicKeys.forEach(publicKey => {
      this.recipientCipher.addKeyRecipient(publicKey.identifier, publicKey.lowLevelPublicKey);
    });
    try {
      this.recipientCipher.addSigner(arg0.identifier, arg0.lowLevelPrivateKey);
      this._isDisposed = false;
      this._isRunning = false;
      this._isFinished = false;
    } catch (error) {
      this.dispose();
      throw error;
    }
  }

  start(length: number) {
    this.ensureLegalState();
    this.recipientCipher.startSignedEncryption(length);
    const messageInfo = this.recipientCipher.packMessageInfo();
    this._isRunning = true;
    return toBuffer(messageInfo);
  }

  update(data: Data) {
    this.ensureLegalState();
    this.ensureIsRunning();
    const myData = dataToUint8Array(data);
    const processEncryption = this.recipientCipher.processEncryption(myData);
    return toBuffer(processEncryption);
  }

  final(dispose = true) {
    this.ensureLegalState();
    this.ensureIsRunning();
    const finishEncryption = this.recipientCipher.finishEncryption();
    const messageInfoFooter = this.recipientCipher.packMessageInfoFooter();
    try {
      return NodeBuffer.concat([finishEncryption, messageInfoFooter]);
    } finally {
      this._isFinished = true;
      this._isRunning = false;
      if (dispose) {
        this.dispose();
      }
    }
  }

  dispose() {
    this.sha512.delete();
    this.aes256Gcm.delete();
    if (this.randomPadding) {
      this.randomPadding.delete();
    }
    if (this.paddingParams) {
      this.paddingParams.delete();
    }
    this.recipientCipher.delete();
    this._isDisposed = true;
  }

  private ensureLegalState() {
    if (this._isDisposed) {
      throw new Error(
        'Illegal state. Cannot use cipher after the `dispose` method has been called.',
      );
    }
    if (this._isFinished) {
      throw new Error('Illegal state. Cannot use cipher after the `final` method has been called.');
    }
  }

  private ensureIsRunning() {
    if (!this._isRunning) {
      throw new Error('Illegal state. Cannot use cipher before the `start` method.');
    }
  }
}
