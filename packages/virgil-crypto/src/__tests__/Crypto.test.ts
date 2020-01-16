import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';
import { NodeBuffer } from '@virgilsecurity/data-utils';

import { hasFoundationModules, setFoundationModules } from '../foundationModules';
import { KeyPairType } from '../KeyPairType';
import { VirgilCrypto } from '../VirgilCrypto';

// https://github.com/VirgilSecurity/virgil-crypto-x/blob/master/Tests/VSM001_CryptoTests.swift
describe('Crypto', () => {
  let virgilCrypto: VirgilCrypto;

  const allKeyTypes = [
    KeyPairType.CURVE25519,
    KeyPairType.ED25519,
    KeyPairType.SECP256R1,
    KeyPairType.RSA_2048,
    KeyPairType.CURVE25519_ROUND5_ED25519_FALCON,
    KeyPairType.CURVE25519_ED25519,
  ];

  const signingKeyTypes = [
    KeyPairType.ED25519,
    KeyPairType.SECP256R1,
    KeyPairType.RSA_2048,
    KeyPairType.CURVE25519_ROUND5_ED25519_FALCON,
    KeyPairType.CURVE25519_ED25519,
  ];

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

  after(() => {
    virgilCrypto.dispose();
  });

  it('test01__key_generation__generate_one_key__should_succeed', () => {
    allKeyTypes.forEach(keyPairType => {
      const keyPair = virgilCrypto.generateKeys(keyPairType);
      expect(NodeBuffer.compare(keyPair.privateKey.identifier, keyPair.publicKey.identifier) === 0)
        .to.be.true;
    });
  });

  it('test02__key_import__all_keys__should_match', () => {
    allKeyTypes.forEach(keyPairType => {
      const keyPair = virgilCrypto.generateKeys(keyPairType);
      const data1 = virgilCrypto.exportPrivateKey(keyPair.privateKey);
      const privateKey = virgilCrypto.importPrivateKey(data1);
      expect(NodeBuffer.compare(privateKey.identifier, keyPair.privateKey.identifier) === 0).to.be
        .true;
      const data2 = virgilCrypto.exportPublicKey(keyPair.publicKey);
      const publicKey = virgilCrypto.importPublicKey(data2);
      expect(NodeBuffer.compare(publicKey.identifier, keyPair.publicKey.identifier) === 0).to.be
        .true;
    });
  });

  it('test03__encryption__some_data__should_match', () => {
    allKeyTypes.forEach(keyPairType => {
      const keyPair1 = virgilCrypto.generateKeys(keyPairType);
      const keyPair2 = virgilCrypto.generateKeys(keyPairType);
      const data = NodeBuffer.from('data', 'utf8');
      const encryptedData = virgilCrypto.encrypt(data, keyPair1.publicKey);
      const decryptedData = virgilCrypto.decrypt(encryptedData, keyPair1.privateKey);
      const error = () => {
        virgilCrypto.decrypt(encryptedData, keyPair2.privateKey);
      };
      expect(decryptedData.equals(data)).to.be.true;
      expect(error).to.throw;
    });
  });

  it('test04__signature__some_data__should_verify', () => {
    signingKeyTypes.forEach(keyPairType => {
      const keyPair1 = virgilCrypto.generateKeys(keyPairType);
      const keyPair2 = virgilCrypto.generateKeys(keyPairType);
      const data = NodeBuffer.from('data', 'utf8');
      const signature = virgilCrypto.calculateSignature(data, keyPair1.privateKey);
      expect(virgilCrypto.verifySignature(data, signature, keyPair1.publicKey)).to.be.true;
      expect(virgilCrypto.verifySignature(data, signature, keyPair2.publicKey)).to.be.false;
    });
  });

  it('test05__sign_and_encrypt__some_data__should_decrypt_and_verify', () => {
    signingKeyTypes.forEach(keyPairType => {
      const keyPair1 = virgilCrypto.generateKeys(keyPairType);
      const keyPair2 = virgilCrypto.generateKeys(keyPairType);
      const keyPair3 = virgilCrypto.generateKeys(keyPairType);
      const data = NodeBuffer.from('data', 'utf8');
      const encrypted = virgilCrypto.signThenEncrypt(data, keyPair1.privateKey, [
        keyPair1.publicKey,
        keyPair2.publicKey,
      ]);
      const decrypted = virgilCrypto.decryptThenVerify(encrypted, keyPair1.privateKey, [
        keyPair1.publicKey,
        keyPair2.publicKey,
      ]);
      const error1 = () => {
        virgilCrypto.decryptThenVerify(encrypted, keyPair3.privateKey, [
          keyPair1.publicKey,
          keyPair2.publicKey,
        ]);
      };
      const error2 = () => {
        virgilCrypto.decryptThenVerify(encrypted, keyPair2.privateKey, keyPair3.publicKey);
      };
      expect(decrypted.equals(data)).to.be.true;
      expect(error1).to.throw;
      expect(error2).to.throw;
    });
  });

  it('test06__sign_stream__file__should_verify', async () => {
    // TODO: add this test
  });

  it('test07__encrypt_stream__file__should_decrypt', () => {
    // TODO: add this test
  });

  it('test08__generate_key_using_seed__fixed_seed__should_match', () => {
    allKeyTypes.forEach(keyPairType => {
      const seed = virgilCrypto.getRandomBytes(32);
      const keyIdentifier = virgilCrypto.generateKeysFromKeyMaterial(seed, keyPairType).privateKey
        .identifier;
      for (let i = 0; i < 5; i += 1) {
        const keyPair = virgilCrypto.generateKeysFromKeyMaterial(seed, keyPairType);
        expect(NodeBuffer.compare(keyPair.privateKey.identifier, keyIdentifier) === 0).to.be.true;
        expect(
          NodeBuffer.compare(keyPair.privateKey.identifier, keyPair.publicKey.identifier) === 0,
        ).to.be.true;
      }
    });
  });

  it('test10__imprort_export_key__random_key__should_match', () => {
    signingKeyTypes.forEach(keyPairType => {
      try {
        const keyPair = virgilCrypto.generateKeys(keyPairType);
        const privateKeyData = virgilCrypto.exportPrivateKey(keyPair.privateKey);
        const publicKeyData = virgilCrypto.exportPublicKey(keyPair.publicKey);
        const privateKey = virgilCrypto.importPrivateKey(privateKeyData);
        const publicKey = virgilCrypto.importPublicKey(publicKeyData);
        virgilCrypto.signThenEncrypt({ value: 'data', encoding: 'utf8' }, privateKey, publicKey);
      } catch (_) {
        expect.fail();
      }
    });
  });

  it('test11__auth_encrypt__random_data__should_match', () => {
    signingKeyTypes.forEach(keyPairType => {
      const keyPair1 = virgilCrypto.generateKeys(keyPairType);
      const keyPair2 = virgilCrypto.generateKeys(keyPairType);
      const keyPair3 = virgilCrypto.generateKeys(keyPairType);
      const data = NodeBuffer.from('data', 'utf8');
      const encrypted = virgilCrypto.signAndEncrypt(
        data,
        keyPair1.privateKey,
        keyPair2.publicKey,
        false,
      );
      const decrypted = virgilCrypto.decryptAndVerify(
        encrypted,
        keyPair2.privateKey,
        keyPair1.publicKey,
      );
      const error1 = () => {
        virgilCrypto.decryptAndVerify(encrypted, keyPair3.privateKey, keyPair1.publicKey);
      };
      const error2 = () => {
        virgilCrypto.decryptAndVerify(encrypted, keyPair2.privateKey, keyPair3.publicKey);
      };
      expect(decrypted.equals(data)).to.be.true;
      expect(error1).to.throw;
      expect(error2).to.throw;
    });
  });

  it('test12__auth_encrypt__stream__should_match', () => {
    // TODO: add this test
  });

  it('test13__auth_encrypt__deprecated__should_work', () => {
    // TODO: add this test
  });

  it('test14__auth_encrypt__padding__should_match', () => {
    signingKeyTypes.forEach(keyPairType => {
      const keyPair1 = virgilCrypto.generateKeys(keyPairType);
      const keyPair2 = virgilCrypto.generateKeys(keyPairType);
      const data = NodeBuffer.from('data', 'utf8');
      const encrypted1 = virgilCrypto.signAndEncrypt(
        data,
        keyPair1.privateKey,
        keyPair2.publicKey,
        true,
      );
      const encrypted2 = virgilCrypto.signThenEncrypt(
        data,
        keyPair1.privateKey,
        keyPair2.publicKey,
        true,
      );
      const decrypted1 = virgilCrypto.decryptAndVerify(
        encrypted1,
        keyPair2.privateKey,
        keyPair1.publicKey,
      );
      const decrypted2 = virgilCrypto.decryptThenVerify(
        encrypted2,
        keyPair2.privateKey,
        keyPair1.publicKey,
      );
      expect(decrypted1.equals(data)).to.be.true;
      expect(decrypted2.equals(data)).to.be.true;
    });
  });
});
