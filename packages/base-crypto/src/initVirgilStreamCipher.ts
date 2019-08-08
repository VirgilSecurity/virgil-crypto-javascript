import { FoundationModules } from '@virgilsecurity/core-foundation';

import { DATA_SIGNATURE_KEY } from './constants';
import { Data } from './types';
import { dataToUint8Array, toArray, toBuffer } from './utils';
import { validatePublicKeysArray } from './validators';
import { VirgilPublicKey } from './VirgilPublicKey';

export const initVirgilStreamCipher = (foundationModules: FoundationModules) =>
  class VirgilStreamCipher {
    isFinished = false;

    _isRunning = false;
    _isDisposed = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _recipientCipher: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _messageInfoCustomParams?: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _aes256Gcm: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _ctrDrbg: any;

    constructor(publicKey: VirgilPublicKey | VirgilPublicKey[], signature?: Data) {
      this._recipientCipher = new foundationModules.RecipientCipher();
      this._aes256Gcm = new foundationModules.Aes256Gcm();
      this._ctrDrbg = new foundationModules.CtrDrbg();
      this._ctrDrbg.setupDefaults();
      this._recipientCipher.encryptionCipher = this._aes256Gcm;
      this._recipientCipher.random = this._ctrDrbg;

      const publicKeys = toArray(publicKey);
      validatePublicKeysArray(publicKeys);

      publicKeys.forEach(myPublicKey => {
        this._recipientCipher.addKeyRecipient(myPublicKey.identifier, myPublicKey.key);
      });

      if (signature) {
        const mySignature = dataToUint8Array(signature);
        this._messageInfoCustomParams = this._recipientCipher.customParams();
        this._messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, mySignature);
      }
    }

    start() {
      this._ensureLegalState();
      this._recipientCipher.startEncryption();
      this._isRunning = true;
      return toBuffer(this._recipientCipher.packMessageInfo());
    }

    update(data: Data) {
      this._ensureLegalState();
      this._ensureIsRunning();
      const myData = dataToUint8Array(data);
      return toBuffer(this._recipientCipher.processEncryption(myData));
    }

    final(dispose: boolean = true) {
      this._ensureLegalState();
      this._ensureIsRunning();
      try {
        return toBuffer(this._recipientCipher.finishEncryption());
      } finally {
        this.isFinished = true;
        this._isRunning = false;
        if (dispose) {
          this.dispose();
        }
      }
    }

    dispose() {
      this._recipientCipher.delete();
      this._aes256Gcm.delete();
      this._ctrDrbg.delete();
      if (this._messageInfoCustomParams) {
        this._messageInfoCustomParams.delete();
      }
      this._isDisposed = true;
    }

    _ensureLegalState() {
      if (this.isFinished) {
        throw new Error(
          'Illegal state. Cannot use cipher after the `final` method has been called.',
        );
      }
      if (this._isDisposed) {
        throw new Error(
          'Illegal state. Cannot use cipher after the `dispose` method has been called.',
        );
      }
    }

    _ensureIsRunning() {
      if (!this._isRunning) {
        throw new Error('Illegal state. Cannot use cipher before the `start` method.');
      }
    }
  };

export type VirgilStreamCipherReturnType = ReturnType<typeof initVirgilStreamCipher>;

export type VirgilStreamCipherType = InstanceType<VirgilStreamCipherReturnType>;
