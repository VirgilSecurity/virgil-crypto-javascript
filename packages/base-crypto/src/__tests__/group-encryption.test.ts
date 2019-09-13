import { NodeBuffer } from '@virgilsecurity/data-utils';
import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';
import { setFoundationModules } from '../foundationModules';
import { VirgilCrypto } from '../VirgilCrypto';
import { HashAlgorithm } from '../HashAlgorithm';
import { generateGroupSession, importGroupSession } from '../groups/group-session';

describe('group encryption', () => {
  let virgilCrypto: VirgilCrypto;

  before(() => {
    return new Promise(resolve => {
      initFoundation().then(foundationModules => {
        setFoundationModules(foundationModules);
        virgilCrypto = new VirgilCrypto();
        resolve();
      });
    });
  });

  describe('generateGroupSession', () => {
    it('throws if groupId is less than 10 bytes long', () => {
      expect(() => {
        generateGroupSession('short_id');
      }, 'should have thrown').throws(Error);
    });

    it('creates group with correct id', () => {
      const expectedId = virgilCrypto.calculateHash(
        'i_am_long_enough_to_be_a_group_id',
        HashAlgorithm.SHA512
      ).slice(0, 32);
      const group = generateGroupSession('i_am_long_enough_to_be_a_group_id');
      expect(group.getSessionId()).to.equal(expectedId.toString('hex'));
    });

    it('creates group with one epoch', () => {
      const group = generateGroupSession('i_am_long_enough_to_be_a_group_id');
      expect(group.export()).to.have.length(1);
    });
  });

  describe('importGroupSession', () => {
    it('reconstructs the group session object from epoch messages', () => {
      const myGroup = generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const epochMessages = myGroup.export();
      const theirGroup = importGroupSession(epochMessages);

      expect(myGroup.getSessionId()).to.equal(theirGroup.getSessionId());
    });
  });

  describe('encrypt and decrypt', () => {
    it('can encrypt and decrypt data', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group = generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      const decrypted = group.decrypt(encrypted, keypair.publicKey);
      expect(decrypted.toString('utf8')).to.equal(plaintext);
    });

    it('decrypt throws if given a wrong public key', () => {
      const plaintext = 'secret';
      const keypair1 = virgilCrypto.generateKeys();
      const keypair2 = virgilCrypto.generateKeys();
      const group = generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair1.privateKey);
      expect(() => group.decrypt(encrypted, keypair2.publicKey)).throws(/Invalid signature/);
    });

    it('cannot decrypt data encrypted by another group', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group1 = generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const group2 = generateGroupSession(NodeBuffer.from('y'.repeat(10)));
      const encrypted = group1.encrypt(plaintext, keypair.privateKey);
      expect(() => group2.decrypt(encrypted, keypair.publicKey)).throws(/Session id doesnt match/);
    });
  });

  describe('addNewEpoch', () => {
    it('adds new epoch message', () => {
      const group = generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      group.addNewEpoch();
      expect(group.export()).to.have.length(2);
    });

    it('can decrypt data from previous epoch', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group = generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      const _ = group.addNewEpoch();
      const decrypted = group.decrypt(encrypted, keypair.publicKey);
      expect(decrypted.toString('utf8')).to.equal(plaintext);
    });

    it('cannot decrypt data from future epochs', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();

      const group = generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      const outdatedGroup = importGroupSession(group.export());
      group.addNewEpoch();
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      expect(() => outdatedGroup.decrypt(encrypted, keypair.publicKey)).throws(/Epoch not found/);
    });
  });
});
