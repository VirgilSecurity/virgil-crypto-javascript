import { FoundationModules } from '@virgilsecurity/core-foundation';

import { DATA_SIGNATURE_KEY } from './constants';
import { getLowLevelPrivateKey } from './privateKeyUtils';
import { Data } from './types';
import { dataToUint8Array, toBuffer } from './utils';
import { validatePrivateKey } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';

export const initVirgilStreamDecipher = (foundationModules: FoundationModules) =>
  class VirgilStreamDecipher {
    isFinished = false;

    _isDisposed = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _recipientCipher: any;

    constructor(privateKey: VirgilPrivateKey) {
      validatePrivateKey(privateKey);
      const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

      this._recipientCipher = new foundationModules.RecipientCipher();

      this._recipientCipher.startDecryptionWithKey(
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
      if (this._isDisposed) {
        throw new Error(
          'Illegal state. Cannot get signature after the `dispose` method has been called.',
        );
      }
      const messageInfoCustomParams = this._recipientCipher.customParams();
      try {
        return toBuffer(messageInfoCustomParams.findData(DATA_SIGNATURE_KEY));
      } finally {
        messageInfoCustomParams.delete();
      }
    }

    update(data: Data) {
      this._ensureLegalState();
      const myData = dataToUint8Array(data);
      return toBuffer(this._recipientCipher.processDecryption(myData));
    }

    final(dispose: boolean = true) {
      this._ensureLegalState();
      try {
        return toBuffer(this._recipientCipher.finishDecryption());
      } finally {
        this.isFinished = true;
        if (dispose) {
          this.dispose();
        }
      }
    }

    dispose() {
      this._recipientCipher.delete();
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
  };

export type VirgilStreamDecipherReturnType = ReturnType<typeof initVirgilStreamDecipher>;

export type VirgilStreamDecipherType = InstanceType<VirgilStreamDecipherReturnType>;
