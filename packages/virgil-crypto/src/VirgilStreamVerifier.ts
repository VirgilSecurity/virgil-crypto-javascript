import { dataToUint8Array } from '@virgilsecurity/data-utils';

import { getFoundationModules } from './foundationModules';
import { Data } from './types';
import { validatePublicKey } from './validators';
import { VirgilPublicKey } from './VirgilPublicKey';

export class VirgilStreamVerifier {
  private _isDisposed = false;
  private verifier: FoundationModules.Verifier;

  get isDisposed() {
    return this._isDisposed;
  }

  constructor(signature: Data) {
    const foundationModules = getFoundationModules();
    const mySignature = dataToUint8Array(signature, 'base64');
    this.verifier = new foundationModules.Verifier();
    try {
      this.verifier.reset(mySignature);
    } catch (error) {
      this.verifier.delete();
      throw error;
    }
  }

  update(data: Data) {
    if (this._isDisposed) {
      throw new Error(
        'Illegal state. Cannot use signer after the `dispose` method has been called.',
      );
    }
    const myData = dataToUint8Array(data, 'utf8');
    this.verifier.appendData(myData);
    return this;
  }

  verify(publicKey: VirgilPublicKey, final = true) {
    if (this._isDisposed) {
      throw new Error(
        'Illegal state. The VirgilStreamVerifier has been disposed. ' +
          'Pass `false` as the second argument to the `verify` method ' +
          'if you need to verify with more than one public key.',
      );
    }
    validatePublicKey(publicKey);
    const result = this.verifier.verify(publicKey.lowLevelPublicKey);
    if (final) {
      this.dispose();
    }
    return result;
  }

  dispose() {
    this.verifier.delete();
    this._isDisposed = true;
  }
}
