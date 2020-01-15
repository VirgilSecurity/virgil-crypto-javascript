import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';
import { NodeBuffer } from '@virgilsecurity/data-utils';

import { hasFoundationModules, setFoundationModules } from '../foundationModules';
import { VirgilCrypto } from '../VirgilCrypto';

import cryptoCompatibilityData from './crypto_compatibility_data.json';

// https://github.com/VirgilSecurity/virgil-virgilCrypto-x/blob/master/Tests/VSM002_CryptoCompatibilityTests.swift
describe('CryptoCompatibility', () => {
  let virgilCrypto: VirgilCrypto;

  before(() => {
    return new Promise(resolve => {
      if (hasFoundationModules()) {
        virgilCrypto = new VirgilCrypto({ useSha256Identifiers: true });
        return resolve();
      }

      initFoundation().then(foundationModules => {
        setFoundationModules(foundationModules);
        virgilCrypto = new VirgilCrypto({ useSha256Identifiers: true });
        resolve();
      });
    });
  });

  after(() => {
    virgilCrypto.dispose();
  });

  it('test002_DecryptFromSingleRecipient_ShouldDecrypt', () => {
    const privateKey = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.encrypt_single_recipient.private_key,
      encoding: 'base64',
    });
    const originalData = NodeBuffer.from(
      cryptoCompatibilityData.encrypt_single_recipient.original_data,
      'base64',
    );
    const cipherData = NodeBuffer.from(
      cryptoCompatibilityData.encrypt_single_recipient.cipher_data,
      'base64',
    );
    const decryptedData = virgilCrypto.decrypt(cipherData, privateKey);
    expect(decryptedData.equals(originalData)).to.be.true;
  });

  it('test003_DecryptFromMultipleRecipients_ShouldDecypt', () => {
    const privateKeys = cryptoCompatibilityData.encrypt_multiple_recipients.private_keys.map(
      privateKey => virgilCrypto.importPrivateKey({ value: privateKey, encoding: 'base64' }),
    );
    const originalData = NodeBuffer.from(
      cryptoCompatibilityData.encrypt_multiple_recipients.original_data,
      'base64',
    );
    const cipherData = NodeBuffer.from(
      cryptoCompatibilityData.encrypt_multiple_recipients.cipher_data,
      'base64',
    );
    privateKeys.forEach(privateKey => {
      expect(virgilCrypto.decrypt(cipherData, privateKey).equals(originalData)).to.be.true;
    });
  });

  it('test004_DecryptAndVerifySingleRecipient_ShouldDecryptAndVerify', () => {
    const privateKey = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.sign_and_encrypt_single_recipient.private_key,
      encoding: 'base64',
    });
    const publicKey = virgilCrypto.extractPublicKey(privateKey);
    const originalData = NodeBuffer.from(
      cryptoCompatibilityData.sign_and_encrypt_single_recipient.original_data,
      'base64',
    );
    const cipherData = NodeBuffer.from(
      cryptoCompatibilityData.sign_and_encrypt_single_recipient.cipher_data,
      'base64',
    );
    const decrypted = virgilCrypto.decryptThenVerify(cipherData, privateKey, publicKey);
    expect(decrypted.equals(originalData)).to.be.true;
  });

  it('test005_DecryptAndVerifyMultipleRecipients_ShouldDecryptAndVerify', () => {
    const privateKeys = cryptoCompatibilityData.sign_and_encrypt_multiple_recipients.private_keys.map(
      privateKey => virgilCrypto.importPrivateKey({ value: privateKey, encoding: 'base64' }),
    );
    const originalData = NodeBuffer.from(
      cryptoCompatibilityData.sign_and_encrypt_multiple_recipients.original_data,
      'base64',
    );
    const cipherData = NodeBuffer.from(
      cryptoCompatibilityData.sign_and_encrypt_multiple_recipients.cipher_data,
      'base64',
    );
    const signerPublicKey = virgilCrypto.extractPublicKey(privateKeys[0]);
    privateKeys.forEach(privateKey => {
      const decrypted = virgilCrypto.decryptThenVerify(cipherData, privateKey, signerPublicKey);
      expect(decrypted.equals(originalData)).to.be.true;
    });
  });

  it('test006_GenerateSignature_ShouldBeEqual', () => {
    expect(true).to.be.true;
    const privateKey = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.generate_signature.private_key,
      encoding: 'base64',
    });
    const originalData = NodeBuffer.from(
      cryptoCompatibilityData.generate_signature.original_data,
      'base64',
    );
    const expectedSignature = NodeBuffer.from(
      cryptoCompatibilityData.generate_signature.signature,
      'base64',
    );
    const signature = virgilCrypto.calculateSignature(originalData, privateKey);
    expect(signature.equals(expectedSignature)).to.be.true;
    expect(
      virgilCrypto.verifySignature(
        originalData,
        expectedSignature,
        virgilCrypto.extractPublicKey(privateKey),
      ),
    ).to.be.true;
  });

  it('test007_DecryptAndVerifyMultipleSigners_ShouldDecryptAndVerify', () => {
    const privateKey = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.sign_and_encrypt_multiple_signers.private_key,
      encoding: 'base64',
    });
    const publicKeys = cryptoCompatibilityData.sign_and_encrypt_multiple_signers.public_keys.map(
      publicKey => virgilCrypto.importPublicKey({ value: publicKey, encoding: 'base64' }),
    );
    const originalData = NodeBuffer.from(
      cryptoCompatibilityData.sign_and_encrypt_multiple_signers.original_data,
      'base64',
    );
    const cipherData = NodeBuffer.from(
      cryptoCompatibilityData.sign_and_encrypt_multiple_signers.cipher_data,
      'base64',
    );
    const decrypted = virgilCrypto.decryptThenVerify(cipherData, privateKey, publicKeys);
    expect(decrypted.equals(originalData)).to.be.true;
  });

  it('test008_GenerateEd25519UsingSeed__ShouldMatch', () => {
    const seed = NodeBuffer.from(
      cryptoCompatibilityData.generate_ed25519_using_seed.seed,
      'base64',
    );
    const { privateKey, publicKey } = virgilCrypto.generateKeysFromKeyMaterial(seed, 'ED25519');
    const expectedPrivateKey = NodeBuffer.from(
      cryptoCompatibilityData.generate_ed25519_using_seed.private_key,
      'base64',
    );
    const expectedPublicKey = NodeBuffer.from(
      cryptoCompatibilityData.generate_ed25519_using_seed.public_key,
      'base64',
    );
    expect(virgilCrypto.exportPrivateKey(privateKey).equals(expectedPrivateKey));
    expect(virgilCrypto.exportPublicKey(publicKey).equals(expectedPublicKey));
  });

  it('test009_AuthEncrypt__ShouldMatch', () => {
    const privateKey1 = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.auth_encrypt.private_key1,
      encoding: 'base64',
    });
    const privateKey2 = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.auth_encrypt.private_key2,
      encoding: 'base64',
    });
    const publicKey2 = virgilCrypto.extractPublicKey(privateKey2);
    const publicKey = virgilCrypto.importPublicKey({
      value: cryptoCompatibilityData.auth_encrypt.public_key,
      encoding: 'base64',
    });
    const dataSha512 = NodeBuffer.from(cryptoCompatibilityData.auth_encrypt.data_sha512, 'base64');
    const cipherData = NodeBuffer.from(cryptoCompatibilityData.auth_encrypt.cipher_data, 'base64');
    const decrypted = virgilCrypto.decryptAndVerify(cipherData, privateKey1, publicKey);
    const sha512 = virgilCrypto.calculateHash(decrypted, virgilCrypto.hashAlgorithm.SHA512);
    expect(sha512.equals(dataSha512)).to.be.true;
    const error1 = () => {
      virgilCrypto.decryptAndVerify(cipherData, privateKey2, publicKey);
    };
    const error2 = () => {
      virgilCrypto.decryptAndVerify(cipherData, privateKey1, publicKey2);
    };
    expect(error1).to.throw;
    expect(error2).to.throw;
  });

  it('test010_AuthEncryptPQ__ShouldMatch', () => {
    const privateKey = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.auth_encrypt_pq.private_key,
      encoding: 'base64',
    });
    const publicKey = virgilCrypto.importPublicKey({
      value: cryptoCompatibilityData.auth_encrypt_pq.public_key,
      encoding: 'base64',
    });
    const dataSha512 = NodeBuffer.from(
      cryptoCompatibilityData.auth_encrypt_pq.data_sha512,
      'base64',
    );
    const cipherData = NodeBuffer.from(
      cryptoCompatibilityData.auth_encrypt_pq.cipher_data,
      'base64',
    );
    const decrypted = virgilCrypto.decryptAndVerify(cipherData, privateKey, publicKey);
    const sha512 = virgilCrypto.calculateHash(decrypted, virgilCrypto.hashAlgorithm.SHA512);
    expect(sha512.equals(dataSha512)).to.be.true;
  });

  it('test011_AuthEncryptPadding__ShouldMatch', () => {
    const privateKey = virgilCrypto.importPrivateKey({
      value: cryptoCompatibilityData.auth_encrypt_padding.private_key,
      encoding: 'base64',
    });
    const publicKey = virgilCrypto.importPublicKey({
      value: cryptoCompatibilityData.auth_encrypt_padding.public_key,
      encoding: 'base64',
    });
    const dataSha512 = NodeBuffer.from(
      cryptoCompatibilityData.auth_encrypt_padding.data_sha512,
      'base64',
    );
    const cipherData = NodeBuffer.from(
      cryptoCompatibilityData.auth_encrypt_padding.cipher_data,
      'base64',
    );
    const decrypted = virgilCrypto.decryptAndVerify(cipherData, privateKey, publicKey);
    const sha512 = virgilCrypto.calculateHash(decrypted, virgilCrypto.hashAlgorithm.SHA512);
    expect(sha512.equals(dataSha512)).to.be.true;
  });
});
