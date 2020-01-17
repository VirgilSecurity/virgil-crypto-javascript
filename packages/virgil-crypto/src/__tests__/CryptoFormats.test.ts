import { expect } from 'chai';

import { NodeBuffer } from '@virgilsecurity/data-utils';

import { initCrypto } from '../foundationModules';
import { VirgilCrypto } from '../VirgilCrypto';

// https://github.com/VirgilSecurity/virgil-crypto-x/blob/master/Tests/VSM003_CryptoFormatsTests.swift
describe('CryptoFormats', () => {
  let virgilCrypto: VirgilCrypto;

  before(async () => {
    await initCrypto();
  });

  beforeEach(() => {
    virgilCrypto = new VirgilCrypto();
  });

  it('test001_SignatureHash', () => {
    const { privateKey } = virgilCrypto.generateKeys();
    const singature = virgilCrypto.calculateSignature(
      { value: 'test', encoding: 'utf8' },
      privateKey,
    );
    const expected = NodeBuffer.from('MFEwDQYJYIZIAWUDBAIDBQA=', 'base64');
    expect(expected.compare(singature, 0, 17) === 0).to.be.true;
  });

  it('test004_KeyIdentifierIsCorrect', () => {
    const keyPair1 = virgilCrypto.generateKeys();
    const identifier1 = NodeBuffer.from(keyPair1.privateKey.identifier);
    const publicKeyHash1 = virgilCrypto.calculateHash(
      virgilCrypto.exportPublicKey(keyPair1.publicKey),
      virgilCrypto.hashAlgorithm.SHA512,
    );
    expect(NodeBuffer.compare(keyPair1.privateKey.identifier, keyPair1.publicKey.identifier) === 0)
      .to.be.true;
    expect(identifier1.compare(publicKeyHash1, 0, 8) === 0).to.be.true;
    const virgilCrypto2 = new VirgilCrypto({ useSha256Identifiers: true });
    const keyPair2 = virgilCrypto2.generateKeys();
    const publicKeyHash2 = virgilCrypto.calculateHash(
      virgilCrypto.exportPublicKey(keyPair2.publicKey),
      virgilCrypto.hashAlgorithm.SHA256,
    );
    expect(publicKeyHash2.equals(keyPair2.privateKey.identifier)).to.be.true;
  });
});
