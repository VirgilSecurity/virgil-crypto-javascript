import { dataToUint8Array } from '@virgilsecurity/data-utils';

import { getFoundationModules } from './foundationModules';
import { importPublicKey } from './keyProvider';
import { Data } from './types';
import { validatePublicKey } from './validators';
import { VirgilPublicKey } from './VirgilPublicKey';

export class VirgilStreamVerifier {
  private isDisposed = false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private verifier: any;

  constructor(signature: Data) {
    const foundationModules = getFoundationModules();
    const mySignature = dataToUint8Array(signature, 'base64');
    this.verifier = new foundationModules.Verifier();
    this.verifier.reset(mySignature);
  }

  update(data: Data) {
    if (this.isDisposed) {
      throw new Error(
        'Illegal state. Cannot use signer after the `dispose` method has been called.',
      );
    }
    const myData = dataToUint8Array(data, 'utf8');
    this.verifier.appendData(myData);
    return this;
  }

  verify(publicKey: VirgilPublicKey, final = true) {
    if (this.isDisposed) {
      throw new Error(
        'Illegal state. The VirgilStreamVerifier has been disposed. ' +
          'Pass `false` as the second argument to the `verify` method ' +
          'if you need to verify with more than one public key.',
      );
    }

    validatePublicKey(publicKey);
    const lowLevelPublicKey = importPublicKey(publicKey.key);

    const result = this.verifier.verify(lowLevelPublicKey);

    lowLevelPublicKey.delete();
    if (final) {
      this.dispose();
    }

    return result;
  }

  dispose() {
    this.verifier.delete();
    this.isDisposed = true;
  }
}
