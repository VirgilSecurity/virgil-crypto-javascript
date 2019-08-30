import { NodeBuffer } from '@virgilsecurity/data-utils';
import { expect } from 'chai';

import { initPythia, VirgilBrainKeyCrypto, VirgilPythiaCrypto } from '../index';
import data from './data.json';

const PASSWORD = 'password';
const TRANSFORMATION_KEY_ID = NodeBuffer.from(data.kTransformationKeyID);
const TWEAK = NodeBuffer.from(data.kTweek);
const PYTHIA_SECRET = NodeBuffer.from(data.kPythiaSecret);
const NEW_PYTHIA_SECRET = NodeBuffer.from(data.kNewPythiaSecret);
const PYTHIA_SCOPE_SECRET = NodeBuffer.from(data.kPythiaScopeSecret);

describe('VirgilPythiaCrypto', () => {
  let virgilBrainKeyCrypto: VirgilBrainKeyCrypto;
  let virgilPythiaCrypto: VirgilPythiaCrypto;

  before(async () => {
    await initPythia();
  });

  beforeEach(() => {
    virgilBrainKeyCrypto = new VirgilBrainKeyCrypto();
    virgilPythiaCrypto = new VirgilPythiaCrypto();
  });

  describe('computeTransformationKeyPair', () => {
    it('computes the transformation key pair deterministically', () => {
      const { privateKey, publicKey } = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      expect(privateKey.equals(NodeBuffer.from(data.kTransformationPrivateKey, 'hex'))).to.be.true;
      expect(publicKey.equals(NodeBuffer.from(data.kTransformationPublicKey, 'hex'))).to.be.true;
    });
  });

  describe('transform', () => {
    it('returns `transformedPassword` and `transformedTweak`', () => {
      const { blindedPassword } = virgilBrainKeyCrypto.blind(PASSWORD);
      const {
        privateKey: transformationPrivateKey,
      } = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      const result = virgilPythiaCrypto.transform({
        blindedPassword,
        transformationPrivateKey,
        tweak: TWEAK,
      });
      expect(Object.keys(result)).to.have.length(2);
      expect(result.transformedPassword).to.be.instanceOf(NodeBuffer);
      expect(result.transformedTweak).to.be.instanceOf(NodeBuffer);
    });
  });

  describe('prove', () => {
    it('returns `proofValueC` and `proofValueU`', () => {
      const { blindedPassword } = virgilBrainKeyCrypto.blind(PASSWORD);
      const transformationKeyPair = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      const { transformedPassword, transformedTweak } = virgilPythiaCrypto.transform({
        blindedPassword,
        tweak: TWEAK,
        transformationPrivateKey: transformationKeyPair.privateKey,
      });
      const result = virgilPythiaCrypto.prove({
        transformedPassword,
        blindedPassword,
        transformedTweak,
        transformationKeyPair,
      });
      expect(Object.keys(result)).to.have.length(2);
      expect(result.proofValueC).to.be.instanceOf(NodeBuffer);
      expect(result.proofValueU).to.be.instanceOf(NodeBuffer);
    });
  });

  describe('verify', () => {
    it('verifies transformed password', () => {
      const { blindedPassword } = virgilBrainKeyCrypto.blind(PASSWORD);
      const transformationKeyPair = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      const { transformedPassword, transformedTweak } = virgilPythiaCrypto.transform({
        blindedPassword,
        tweak: TWEAK,
        transformationPrivateKey: transformationKeyPair.privateKey,
      });
      const { proofValueC, proofValueU } = virgilPythiaCrypto.prove({
        transformedPassword,
        blindedPassword,
        transformedTweak,
        transformationKeyPair,
      });
      const verified = virgilPythiaCrypto.verify({
        transformedPassword,
        blindedPassword,
        proofValueC,
        proofValueU,
        tweak: TWEAK,
        transformationPublicKey: transformationKeyPair.publicKey,
      });
      expect(verified).to.be.true;
    });
  });

  describe('getPasswordUpdateToken', () => {
    it('returns password update token', () => {
      const oldTransformationKeyPair = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      const newTransformationKeyPair = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: NEW_PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      const updateToken = virgilPythiaCrypto.getPasswordUpdateToken({
        oldTransformationPrivateKey: oldTransformationKeyPair.privateKey,
        newTransformationPrivateKey: newTransformationKeyPair.privateKey,
      });
      expect(updateToken).to.be.instanceOf(NodeBuffer);
    });
  });

  describe('updateDeblindedWithToken', () => {
    it('updates deblinded password with token', () => {
      const { blindingSecret, blindedPassword } = virgilBrainKeyCrypto.blind(PASSWORD);
      const oldTransformationKeyPair = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      const { transformedPassword } = virgilPythiaCrypto.transform({
        blindedPassword,
        tweak: TWEAK,
        transformationPrivateKey: oldTransformationKeyPair.privateKey,
      });
      const deblindedPassword = virgilBrainKeyCrypto.deblind({
        transformedPassword,
        blindingSecret,
      });
      const newTransformationKeyPair = virgilPythiaCrypto.computeTransformationKeyPair({
        transformationKeyId: TRANSFORMATION_KEY_ID,
        pythiaSecret: NEW_PYTHIA_SECRET,
        pythiaScopeSecret: PYTHIA_SCOPE_SECRET,
      });
      const updateToken = virgilPythiaCrypto.getPasswordUpdateToken({
        oldTransformationPrivateKey: oldTransformationKeyPair.privateKey,
        newTransformationPrivateKey: newTransformationKeyPair.privateKey,
      });
      const updatedDeblindedPassword = virgilPythiaCrypto.updateDeblindedWithToken({
        deblindedPassword,
        updateToken,
      });
      const {
        blindingSecret: newBlindingSecret,
        blindedPassword: newBlindedPassword,
      } = virgilBrainKeyCrypto.blind(PASSWORD);
      const { transformedPassword: newTransformedPassword } = virgilPythiaCrypto.transform({
        blindedPassword: newBlindedPassword,
        tweak: TWEAK,
        transformationPrivateKey: newTransformationKeyPair.privateKey,
      });
      const newDeblindedPassword = virgilBrainKeyCrypto.deblind({
        transformedPassword: newTransformedPassword,
        blindingSecret: newBlindingSecret,
      });
      expect(updatedDeblindedPassword.equals(newDeblindedPassword)).to.be.true;
    });
  });
});
