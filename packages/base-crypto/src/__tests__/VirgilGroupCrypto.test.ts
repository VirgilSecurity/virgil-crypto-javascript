/// <reference types="mocha" />

import { NodeBuffer } from '@virgilsecurity/data-utils';
import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';
import { setFoundationModules } from '../foundationModules';
import { VirgilGroupCrypto } from '../groups/VirgilGroupCrypto';
import { VirgilCrypto } from '../VirgilCrypto';

describe.only('VirgilGroupCrypto', () => {
  let virgilCrypto: VirgilCrypto;
  let virgilGroupCrypto: VirgilGroupCrypto;

  before(() => {
    return new Promise(resolve => {
      initFoundation().then(foundationModules => {
        setFoundationModules(foundationModules);
        virgilCrypto = new VirgilCrypto();
        virgilGroupCrypto = new VirgilGroupCrypto();
        resolve();
      });
    });
  });

  describe('createGroup', () => {
    it('throws if groupId is less than 10 bytes long', () => {
      expect(() => {
        virgilGroupCrypto.createGroup('short_id');
      }, 'should have thrown').throws(Error);
    });

    it('creates group with one ticket', () => {
      const group = virgilGroupCrypto.createGroup('i_am_long_enough_to_be_a_group_id');
      expect(group).to.be.ok;
    });
  });

  describe('encrypt and decrypt', () => {
    it('can encrypt data', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group = virgilGroupCrypto.createGroup(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      const decrypted = group.decrypt(encrypted, keypair.publicKey);
      expect(decrypted.toString('utf8')).to.equal(plaintext);
    });

    it('decrypt throws if given a wrong public key', () => {
      const plaintext = 'secret';
      const keypair1 = virgilCrypto.generateKeys();
      const keypair2 = virgilCrypto.generateKeys();
      const group = virgilGroupCrypto.createGroup(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair1.privateKey);
      expect(() => group.decrypt(encrypted, keypair2.publicKey)).throws(/Invalid signature/);
    });

    it('cannot decrypt data encrypted by another group', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group1 = virgilGroupCrypto.createGroup(NodeBuffer.from('x'.repeat(10)));
      const group2 = virgilGroupCrypto.createGroup(NodeBuffer.from('y'.repeat(10)));
      const encrypted = group1.encrypt(plaintext, keypair.privateKey);
      expect(() => group2.decrypt(encrypted, keypair.publicKey)).throws(/Session id doesnt match/);
    });
  });

  describe('addNewTicket', () => {
    it('can decrypt after adding new ticket', () => {
      const plaintext = 'secret';
      const keypair = virgilCrypto.generateKeys();
      const group = virgilGroupCrypto.createGroup(NodeBuffer.from('x'.repeat(10)));
      const encrypted = group.encrypt(plaintext, keypair.privateKey);
      group.addNewTicket();
      const decrypted = group.decrypt(encrypted, keypair.publicKey);
      expect(decrypted.toString('utf8')).to.equal(plaintext);
    });
  });
});
