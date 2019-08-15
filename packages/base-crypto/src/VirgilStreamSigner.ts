import { getFoundationModules } from './foundationModules';
import { getLowLevelPrivateKey } from './privateKeyUtils';
import { Data } from './types';
import { dataToUint8Array, toBuffer } from './utils';
import { validatePrivateKey } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';

export class VirgilStreamSigner {
  private isDisposed: boolean = false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private signer: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private sha512: any;

  constructor() {
    const foundationModules = getFoundationModules();
    this.signer = new foundationModules.Signer();
    this.sha512 = new foundationModules.Sha512();
    this.signer.hash = this.sha512;
    this.signer.reset();
  }

  update(data: Data) {
    if (this.isDisposed) {
      throw new Error(
        'Illegal state. Cannot use signer after the `dispose` method has been called.',
      );
    }
    const myData = dataToUint8Array(data, 'utf8');
    this.signer.appendData(myData);
    return this;
  }

  sign(privateKey: VirgilPrivateKey, final: boolean = true) {
    if (this.isDisposed) {
      throw new Error(
        'Illegal state. The VirgilStreamSigner has been disposed. ' +
          'Pass `false` as the second argument to the `sign` method ' +
          'if you need to generate more than one signature.',
      );
    }

    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    try {
      return toBuffer(this.signer.sign(lowLevelPrivateKey));
    } finally {
      if (final) {
        this.dispose();
      }
    }
  }

  dispose() {
    this.signer.delete();
    this.sha512.delete();
  }
}
