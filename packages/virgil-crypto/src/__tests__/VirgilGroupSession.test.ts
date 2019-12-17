import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';
import { NodeBuffer } from '@virgilsecurity/data-utils';

import { hasFoundationModules, setFoundationModules } from '../foundationModules';
import { VirgilCrypto } from '../VirgilCrypto';

describe('group encryption', () => {
  let virgilCrypto: VirgilCrypto;

  before(() => {
    return new Promise(resolve => {
      if (hasFoundationModules()) {
        virgilCrypto = new VirgilCrypto();
        return resolve();
      }

      initFoundation().then(foundationModules => {
        setFoundationModules(foundationModules);
        virgilCrypto = new VirgilCrypto();
        resolve();
      });
    });
  });

  describe('addNewEpoch', () => {
    it('adds new epoch message', () => {
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      group.addNewEpoch();
      group.addNewEpoch();
      expect(group.export()).to.have.length(3);
    });

    it('increments the currentEpochNumber', () => {
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const oldEpochNumber = group.getCurrentEpochNumber();
      group.addNewEpoch();
      expect(group.getCurrentEpochNumber()).not.to.equal(oldEpochNumber);
    });

    it('returns epochNumber, sessionId and data from epoch message', () => {
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const { epochNumber, sessionId, data } = group.addNewEpoch();
      expect(epochNumber).to.equal(group.getCurrentEpochNumber());
      expect(sessionId).to.equal(group.getSessionId());
      const lastEpochData = group.export().pop();
      expect(lastEpochData).not.to.be.undefined;
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(lastEpochData!.toString('base64')).to.equal(data);
    });
  });

  describe('getCurrentEpochNumber', () => {
    it('returns zero for new group', () => {
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      expect(group.getCurrentEpochNumber()).to.equal(0);
    });

    it('increments after adding new epoch', () => {
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      group.addNewEpoch();
      expect(group.getCurrentEpochNumber()).to.equal(1);
    });
  });

  describe('parseMessage', () => {
    it('returns epochNumber, sessionId and data from encrypted message', () => {
      const keypair = virgilCrypto.generateKeys();
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt('secret', keypair.privateKey);
      const { epochNumber, sessionId, data } = group.parseMessage(encrypted);
      expect(epochNumber).to.equal(group.getCurrentEpochNumber());
      expect(sessionId).to.equal(group.getSessionId());
      expect(encrypted.toString('base64')).to.equal(data);
    });
  });

  describe('encrypt and decrypt', () => {
    it('can encrypt and decrypt data', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      const decrypted = group.decrypt(encrypted, keypair.publicKey);
      expect(decrypted.toString('utf8')).to.equal(plaintext);
    });

    it('decrypt throws if given a wrong public key', () => {
      const plaintext = 'secret';
      const keypair1 = virgilCrypto.generateKeys();
      const keypair2 = virgilCrypto.generateKeys();
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair1.privateKey);
      expect(() => group.decrypt(encrypted, keypair2.publicKey)).throws(/Invalid signature/);
    });

    it('cannot decrypt data encrypted by another group', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group1 = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const group2 = virgilCrypto.generateGroupSession(NodeBuffer.from('y'.repeat(10)));
      const encrypted = group1.encrypt(plaintext, keypair.privateKey);
      expect(() => group2.decrypt(encrypted, keypair.publicKey)).throws(/Session id doesnt match/);
    });

    it('can decrypt data from previous epoch', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      group.addNewEpoch();
      const decrypted = group.decrypt(encrypted, keypair.publicKey);
      expect(decrypted.toString('utf8')).to.equal(plaintext);
    });

    it('cannot decrypt data from future epochs', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();

      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const outdatedGroup = virgilCrypto.importGroupSession(group.export());
      group.addNewEpoch();
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      expect(() => outdatedGroup.decrypt(encrypted, keypair.publicKey)).throws(/Epoch not found/);
    });
  });

  describe('export', () => {
    it('returns current epoch messages as array', () => {
      const group = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      group.addNewEpoch();
      group.addNewEpoch();
      group.addNewEpoch();
      const epochMessages = group.export();
      expect(epochMessages).to.have.length(4); // 1 initial and 3 added manually
    });
  });
});
