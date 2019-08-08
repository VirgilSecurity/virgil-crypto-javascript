import { FoundationModules } from '@virgilsecurity/core-foundation';

import { Data } from './types';
import { dataToUint8Array } from './utils';
import { validatePublicKey } from './validators';
import { VirgilPublicKey } from './VirgilPublicKey';

export const initVirgilStreamVerifier = (foundationModules: FoundationModules) =>
  class VirgilStreamVerifier {
    _isDisposed = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _verifier: any;

    constructor(signature: Data) {
      const mySignature = dataToUint8Array(signature);
      this._verifier = new foundationModules.Verifier();
      this._verifier.reset(mySignature);
    }

    update(data: Data) {
      if (this._isDisposed) {
        throw new Error(
          'Illegal state. Cannot use signer after the `dispose` method has been called.',
        );
      }
      const myData = dataToUint8Array(data);
      this._verifier.appendData(myData);
      return this;
    }

    verify(publicKey: VirgilPublicKey, final: boolean = true) {
      if (this._isDisposed) {
        throw new Error(
          'Illegal state. The VirgilStreamVerifier has been disposed. ' +
            'Pass `false` as the second argument to the `verify` method ' +
            'if you need to verify with more than one public key.',
        );
      }

      validatePublicKey(publicKey);

      try {
        return this._verifier.verify(publicKey.key);
      } finally {
        if (final) {
          this.dispose();
        }
      }
    }

    dispose() {
      this._verifier.delete();
      this._isDisposed = true;
    }
  };

export type VirgilStreamVerifierReturnType = ReturnType<typeof initVirgilStreamVerifier>;

export type VirgilStreamVerifierType = InstanceType<VirgilStreamVerifierReturnType>;
