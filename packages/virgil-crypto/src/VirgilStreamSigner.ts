import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getFoundationModules } from './foundationModules';
import { getRandom } from './globalInstances';
import { Data } from './types';
import { validatePrivateKey } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';

export class VirgilStreamSigner {
  private _isDisposed = false;

  private readonly signer: FoundationModules.Signer;
  private readonly sha512: FoundationModules.Sha512;

  get isDisposed() {
    return this._isDisposed;
  }

  constructor() {
    const foundationModules = getFoundationModules();
    this.signer = new foundationModules.Signer();
    this.sha512 = new foundationModules.Sha512();
    this.signer.hash = this.sha512;
    this.signer.random = getRandom();
    this.signer.reset();
  }

  update(data: Data) {
    if (this._isDisposed) {
      throw new Error(
        'Illegal state. Cannot use signer after the `dispose` method has been called.',
      );
    }
    const myData = dataToUint8Array(data, 'utf8');
    this.signer.appendData(myData);
    return this;
  }

  sign(privateKey: VirgilPrivateKey, final = true) {
    if (this._isDisposed) {
      throw new Error(
        'Illegal state. The VirgilStreamSigner has been disposed. ' +
          'Pass `false` as the second argument to the `sign` method ' +
          'if you need to generate more than one signature.',
      );
    }
    validatePrivateKey(privateKey);
    const result = this.signer.sign(privateKey.lowLevelPrivateKey);
    if (final) {
      this.dispose();
    }
    return toBuffer(result);
  }

  dispose() {
    this.sha512.delete();
    this.signer.delete();
    this._isDisposed = true;
  }
}
