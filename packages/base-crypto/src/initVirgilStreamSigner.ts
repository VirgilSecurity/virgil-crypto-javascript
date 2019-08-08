import { FoundationModules } from '@virgilsecurity/core-foundation';

import { getLowLevelPrivateKey } from './privateKeyUtils';
import { Data } from './types';
import { dataToUint8Array, toBuffer } from './utils';
import { validatePrivateKey } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';

export const initVirgilStreamSigner = (foundationModules: FoundationModules) =>
  class VirgilStreamSigner {
    _isDisposed: boolean = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _signer: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _sha512: any;

    constructor() {
      this._signer = new foundationModules.Signer();
      this._sha512 = new foundationModules.Sha512();
      this._signer.hash = this._sha512;
      this._signer.reset();
    }

    update(data: Data) {
      if (this._isDisposed) {
        throw new Error(
          'Illegal state. Cannot use signer after the `dispose` method has been called.',
        );
      }
      const myData = dataToUint8Array(data);
      this._signer.appendData(myData);
      return this;
    }

    sign(privateKey: VirgilPrivateKey, final: boolean = true) {
      if (this._isDisposed) {
        throw new Error(
          'Illegal state. The VirgilStreamSigner has been disposed. ' +
            'Pass `false` as the second argument to the `sign` method ' +
            'if you need to generate more than one signature.',
        );
      }

      validatePrivateKey(privateKey);
      const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

      try {
        return toBuffer(this._signer.sign(lowLevelPrivateKey));
      } finally {
        if (final) {
          this.dispose();
        }
      }
    }

    dispose() {
      this._signer.delete();
      this._sha512.delete();
    }
  };

export type VirgilStreamSignerReturnType = ReturnType<typeof initVirgilStreamSigner>;

export type VirgilStreamSignerType = InstanceType<VirgilStreamSignerReturnType>;
