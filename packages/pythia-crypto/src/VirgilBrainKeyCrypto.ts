import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPythiaModules } from './pythiaModules';
import { Data, IBrainKeyCrypto } from './types';

export class VirgilBrainKeyCrypto implements IBrainKeyCrypto {
  blind(password: Data) {
    const { Pythia } = getPythiaModules();
    const myPassword = dataToUint8Array(password, 'utf8');
    const { blindedPassword, blindingSecret } = Pythia.blind(myPassword);
    return {
      blindedPassword: toBuffer(blindedPassword),
      blindingSecret: toBuffer(blindingSecret),
    };
  }

  deblind(options: { transformedPassword: Data; blindingSecret: Data }) {
    const { Pythia } = getPythiaModules();
    const myTransformedPassword = dataToUint8Array(options.transformedPassword, 'base64');
    const myBlindingSecret = dataToUint8Array(options.blindingSecret, 'base64');
    const result = Pythia.deblind(myTransformedPassword, myBlindingSecret);
    return toBuffer(result);
  }
}
