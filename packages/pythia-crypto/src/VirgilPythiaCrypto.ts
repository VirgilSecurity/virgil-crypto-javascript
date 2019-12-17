import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPythiaModules } from './pythiaModules';
import { Data, IPythiaTransformationKeyPair, IPythiaCrypto } from './types';
import { VirgilBrainKeyCrypto } from './VirgilBrainKeyCrypto';

export class VirgilPythiaCrypto implements IPythiaCrypto {
  private readonly virgilBrainKeyCrypto: VirgilBrainKeyCrypto;

  constructor(virgilBrainKeyCrypto?: VirgilBrainKeyCrypto) {
    this.virgilBrainKeyCrypto = virgilBrainKeyCrypto || new VirgilBrainKeyCrypto();
  }

  blind(password: Data) {
    return this.virgilBrainKeyCrypto.blind(password);
  }

  deblind(options: { transformedPassword: Data; blindingSecret: Data }) {
    return this.virgilBrainKeyCrypto.deblind(options);
  }

  computeTransformationKeyPair(options: {
    transformationKeyId: Data;
    pythiaSecret: Data;
    pythiaScopeSecret: Data;
  }) {
    const { Pythia } = getPythiaModules();
    const myTransformationKeyId = dataToUint8Array(options.transformationKeyId, 'base64');
    const myPythiaSecret = dataToUint8Array(options.pythiaSecret, 'base64');
    const myPythiaScopeSecret = dataToUint8Array(options.pythiaScopeSecret, 'base64');
    const {
      transformationPrivateKey,
      transformationPublicKey,
    } = Pythia.computeTransformationKeyPair(
      myTransformationKeyId,
      myPythiaSecret,
      myPythiaScopeSecret,
    );
    return {
      privateKey: toBuffer(transformationPrivateKey),
      publicKey: toBuffer(transformationPublicKey),
    };
  }

  transform(options: { blindedPassword: Data; tweak: Data; transformationPrivateKey: Data }) {
    const { Pythia } = getPythiaModules();
    const myBlindedPassword = dataToUint8Array(options.blindedPassword, 'base64');
    const myTweak = dataToUint8Array(options.tweak, 'base64');
    const myTransformationPrivateKey = dataToUint8Array(options.transformationPrivateKey, 'base64');
    const { transformedPassword, transformedTweak } = Pythia.transform(
      myBlindedPassword,
      myTweak,
      myTransformationPrivateKey,
    );
    return {
      transformedPassword: toBuffer(transformedPassword),
      transformedTweak: toBuffer(transformedTweak),
    };
  }

  prove(options: {
    transformedPassword: Data;
    blindedPassword: Data;
    transformedTweak: Data;
    transformationKeyPair: IPythiaTransformationKeyPair;
  }) {
    const { Pythia } = getPythiaModules();
    const myTransformedPassword = dataToUint8Array(options.transformedPassword, 'base64');
    const myBlindedPassword = dataToUint8Array(options.blindedPassword, 'base64');
    const myTransformedTweak = dataToUint8Array(options.transformedTweak, 'base64');
    const { proofValueC, proofValueU } = Pythia.prove(
      myTransformedPassword,
      myBlindedPassword,
      myTransformedTweak,
      options.transformationKeyPair.privateKey,
      options.transformationKeyPair.publicKey,
    );
    return {
      proofValueC: toBuffer(proofValueC),
      proofValueU: toBuffer(proofValueU),
    };
  }

  verify(options: {
    transformedPassword: Data;
    blindedPassword: Data;
    tweak: Data;
    transformationPublicKey: Data;
    proofValueC: Data;
    proofValueU: Data;
  }) {
    const { Pythia } = getPythiaModules();
    const myTransformedPassword = dataToUint8Array(options.transformedPassword, 'base64');
    const myBlindedPassword = dataToUint8Array(options.blindedPassword, 'base64');
    const myTweak = dataToUint8Array(options.tweak, 'base64');
    const myTransformationPublicKey = dataToUint8Array(options.transformationPublicKey, 'base64');
    const myProofValueC = dataToUint8Array(options.proofValueC, 'base64');
    const myProofValueU = dataToUint8Array(options.proofValueU, 'base64');
    return Pythia.verify(
      myTransformedPassword,
      myBlindedPassword,
      myTweak,
      myTransformationPublicKey,
      myProofValueC,
      myProofValueU,
    );
  }

  getPasswordUpdateToken(options: {
    oldTransformationPrivateKey: Data;
    newTransformationPrivateKey: Data;
  }) {
    const { Pythia } = getPythiaModules();
    const myOldTransformationPrivateKey = dataToUint8Array(
      options.oldTransformationPrivateKey,
      'base64',
    );
    const myNewTransformationPrivateKey = dataToUint8Array(
      options.newTransformationPrivateKey,
      'base64',
    );
    const passwordUpdateToken = Pythia.getPasswordUpdateToken(
      myOldTransformationPrivateKey,
      myNewTransformationPrivateKey,
    );
    return toBuffer(passwordUpdateToken);
  }

  updateDeblindedWithToken(options: { deblindedPassword: Data; updateToken: Data }) {
    const { Pythia } = getPythiaModules();
    const myDeblindedPassword = dataToUint8Array(options.deblindedPassword, 'base64');
    const myUpdateToken = dataToUint8Array(options.updateToken, 'base64');
    const result = Pythia.updateDeblindedWithToken(myDeblindedPassword, myUpdateToken);
    return toBuffer(result);
  }
}
