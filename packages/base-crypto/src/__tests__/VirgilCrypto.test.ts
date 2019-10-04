import { NodeBuffer } from '@virgilsecurity/data-utils';
import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';

import {
  setFoundationModules,
  hasFoundationModules,
  HashAlgorithm,
  VirgilCrypto,
  VirgilPrivateKey,
  VirgilPublicKey,
  VirgilStreamCipher,
  VirgilStreamDecipher,
  VirgilStreamSigner,
  VirgilStreamVerifier,
} from '..';

describe('VirgilCrypto', () => {
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

  describe('generateKeys', () => {
    it('returns key pair', () => {
      const keyPair = virgilCrypto.generateKeys();
      expect(keyPair.privateKey).to.be.instanceOf(VirgilPrivateKey);
      expect(keyPair.publicKey).to.be.instanceOf(VirgilPublicKey);
    });

    it('uses SHA512 identifiers by default', () => {
      const keyPair = virgilCrypto.generateKeys();
      const publicKeyDer = virgilCrypto.exportPublicKey(keyPair.publicKey);
      const publicKeyHash = virgilCrypto.calculateHash(publicKeyDer, HashAlgorithm.SHA512);
      expect(publicKeyHash.slice(0, 8).equals(keyPair.publicKey.identifier)).to.be.true;
    });

    it('uses SHA256 identifiers', () => {
      const virgilCrypto256 = new VirgilCrypto({ useSha256Identifiers: true });
      const keyPair = virgilCrypto256.generateKeys();
      const publicKeyDer = virgilCrypto256.exportPublicKey(keyPair.publicKey);
      const publicKeyHash = virgilCrypto256.calculateHash(publicKeyDer, HashAlgorithm.SHA256);
      expect(publicKeyHash.equals(keyPair.publicKey.identifier)).to.be.true;
    });
  });

  describe('generateKeysFromKeyMaterial', () => {
    it('returns key pair', () => {
      const seed = virgilCrypto.getRandomBytes(32);
      const keyPair = virgilCrypto.generateKeysFromKeyMaterial(seed);
      expect(keyPair.privateKey).to.be.instanceOf(VirgilPrivateKey);
      expect(keyPair.publicKey).to.be.instanceOf(VirgilPublicKey);
    });

    it('returns same keys from the same seed', () => {
      const seed = virgilCrypto.getRandomBytes(32);
      const keyPair1 = virgilCrypto.generateKeysFromKeyMaterial(seed);
      const keyPair2 = virgilCrypto.generateKeysFromKeyMaterial(seed);
      const privateKey1 = virgilCrypto.exportPrivateKey(keyPair1.privateKey);
      const privateKey2 = virgilCrypto.exportPrivateKey(keyPair2.privateKey);
      expect(privateKey1.equals(privateKey2)).to.be.true;
    });

    it('returns different keys from different seeds', () => {
      const seed1 = virgilCrypto.getRandomBytes(32);
      const seed2 = virgilCrypto.getRandomBytes(32);
      const keyPair1 = virgilCrypto.generateKeysFromKeyMaterial(seed1);
      const keyPair2 = virgilCrypto.generateKeysFromKeyMaterial(seed2);
      const privateKey1 = virgilCrypto.exportPrivateKey(keyPair1.privateKey);
      const privateKey2 = virgilCrypto.exportPrivateKey(keyPair2.privateKey);
      expect(privateKey1.equals(privateKey2)).to.be.false;
    });
  });

  it('importPrivateKey -> exportPrivateKey', () => {
    const privateKeyHex =
      '302e020100300506032b6570042204204ac70df9ed0d8e54c7537181097f53f30e171474d2322c3f91438d1bbef75e73';
    const privateKey = virgilCrypto.importPrivateKey({ value: privateKeyHex, encoding: 'hex' });
    const exportedKey = virgilCrypto.exportPrivateKey(privateKey);
    expect(exportedKey.toString('hex')).to.equal(privateKeyHex);
  });

  it('importPublicKey -> exportPublicKey', () => {
    const publicKeyHex =
      '302a300506032b65700321005da627bebb5f5edc843b649a60d2db9886c0ede6a1f24289aed4f13e59935539';
    const publicKey = virgilCrypto.importPublicKey({ value: publicKeyHex, encoding: 'hex' });
    const exportedKey = virgilCrypto.exportPublicKey(publicKey);
    expect(exportedKey.toString('hex')).to.equal(publicKeyHex);
  });

  it('encrypt -> decrypt', () => {
    const data = 'data';
    const keyPair = virgilCrypto.generateKeys();
    const cipherData = virgilCrypto.encrypt({ value: data, encoding: 'utf8' }, keyPair.publicKey);
    const decryptedData = virgilCrypto.decrypt(cipherData, keyPair.privateKey);
    expect(decryptedData.toString()).to.equal(data);
  });

  it('throws if `encrypt` is called with an empty array of recipients', () => {
    const error = () => {
      virgilCrypto.encrypt({ value: 'secret message', encoding: 'utf8' }, []);
    };
    expect(error).to.throw;
  });

  describe('calculateHash', () => {
    it('produces correct hash', () => {
      const hash = virgilCrypto.calculateHash({ value: 'data', encoding: 'utf8' });
      const expectedHash = NodeBuffer.from(
        '77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876',
        'hex',
      );
      expect(hash.equals(expectedHash)).to.be.true;
    });

    it('produces the same hash for the same data', () => {
      const hash1 = virgilCrypto.calculateHash({ value: 'data', encoding: 'utf8' });
      const hash2 = virgilCrypto.calculateHash({ value: 'data', encoding: 'utf8' });
      expect(hash1.equals(hash2)).to.be.true;
    });

    it('produces different hash for different algorithms', () => {
      const hash1 = virgilCrypto.calculateHash(
        { value: 'data', encoding: 'utf8' },
        HashAlgorithm.SHA256,
      );
      const hash2 = virgilCrypto.calculateHash(
        { value: 'data', encoding: 'utf8' },
        HashAlgorithm.SHA384,
      );
      expect(hash1.equals(hash2)).to.be.false;
    });
  });

  it('extractPublicKey', () => {
    const keyPair = virgilCrypto.generateKeys();
    const publicKey = virgilCrypto.extractPublicKey(keyPair.privateKey);
    const key1 = virgilCrypto.exportPublicKey(keyPair.publicKey);
    const key2 = virgilCrypto.exportPublicKey(publicKey);
    expect(key1.equals(key2)).to.be.true;
  });

  it('calculateSignature -> verifySignature', () => {
    const data = 'data';
    const keyPair = virgilCrypto.generateKeys();
    const signature = virgilCrypto.calculateSignature(
      { value: data, encoding: 'utf8' },
      keyPair.privateKey,
    );
    const isValid = virgilCrypto.verifySignature(
      { value: data, encoding: 'utf8' },
      signature,
      keyPair.publicKey,
    );
    expect(isValid).to.be.true;
  });

  describe('signThenEncrypt -> decryptThenVerify', () => {
    it('decrypts and verifies', () => {
      const senderKeyPair = virgilCrypto.generateKeys();
      const recipientKeyPair = virgilCrypto.generateKeys();
      const message = 'Secret message';
      const cipherData = virgilCrypto.signThenEncrypt(
        { value: message, encoding: 'utf8' },
        senderKeyPair.privateKey,
        recipientKeyPair.publicKey,
      );
      const decryptedMessage = virgilCrypto.decryptThenVerify(
        cipherData,
        recipientKeyPair.privateKey,
        senderKeyPair.publicKey,
      );
      expect(decryptedMessage.toString()).to.equal(message);
    });

    it('decrypts and verifies given the right keys', () => {
      const data = NodeBuffer.from('Secret message');
      const senderKeyPair = virgilCrypto.generateKeys();
      const recipientKeyPair = virgilCrypto.generateKeys();
      const additionalKeyPair = virgilCrypto.generateKeys();
      const anotherKeyPair = virgilCrypto.generateKeys();
      const encryptedData = virgilCrypto.signThenEncrypt(
        data,
        senderKeyPair.privateKey,
        recipientKeyPair.publicKey,
      );
      const decryptedData = virgilCrypto.decryptThenVerify(
        encryptedData,
        recipientKeyPair.privateKey,
        [additionalKeyPair.publicKey, anotherKeyPair.publicKey, senderKeyPair.publicKey],
      );
      expect(decryptedData.equals(data)).to.be.true;
    });

    it('fails verification given the wrong keys', () => {
      const data = NodeBuffer.from('Secret message');
      const senderKeyPair = virgilCrypto.generateKeys();
      const recipientKeyPair = virgilCrypto.generateKeys();
      const additionalKeyPair = virgilCrypto.generateKeys();
      const anotherKeyPair = virgilCrypto.generateKeys();
      const encryptedData = virgilCrypto.signThenEncrypt(
        data,
        senderKeyPair.privateKey,
        recipientKeyPair.publicKey,
      );
      const error = () => {
        virgilCrypto.decryptThenVerify(encryptedData, recipientKeyPair.privateKey, [
          additionalKeyPair.publicKey,
          anotherKeyPair.publicKey,
        ]);
      };
      expect(error).to.throw;
    });
  });

  it('getRandomBytes', () => {
    const length = 4;
    const randomBytes = virgilCrypto.getRandomBytes(length);
    expect(randomBytes.byteLength === length).to.be.true;
  });

  it('signThenEncryptDetached -> decryptThenVerifyDetached', () => {
    const data = NodeBuffer.from('data', 'utf8');
    const { privateKey, publicKey } = virgilCrypto.generateKeys();
    const { encryptedData, metadata } = virgilCrypto.signThenEncryptDetached(
      data,
      privateKey,
      publicKey,
    );
    const decrypted = virgilCrypto.decryptThenVerifyDetached(
      encryptedData,
      metadata,
      privateKey,
      publicKey,
    );
    expect(decrypted.equals(data)).to.be.true;
  });

  it('createStreamCipher', () => {
    const { publicKey } = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(publicKey);
    expect(streamCipher).to.be.instanceOf(VirgilStreamCipher);
  });

  it('createStreamDecipher', () => {
    const { privateKey } = virgilCrypto.generateKeys();
    const streamDecipher = virgilCrypto.createStreamDecipher(privateKey);
    expect(streamDecipher).to.be.instanceOf(VirgilStreamDecipher);
  });

  it('createStreamSigner', () => {
    const streamSigner = virgilCrypto.createStreamSigner();
    expect(streamSigner).to.be.instanceOf(VirgilStreamSigner);
  });

  it('createStreamVerifier', () => {
    const keyPair = virgilCrypto.generateKeys();
    const signature = virgilCrypto.calculateSignature(
      { value: 'data', encoding: 'utf8' },
      keyPair.privateKey,
    );
    const streamVerifier = virgilCrypto.createStreamVerifier(signature);
    expect(streamVerifier).to.be.instanceOf(VirgilStreamVerifier);
  });

  describe('generateGroupSession', () => {
    it('throws if groupId is less than 10 bytes long', () => {
      expect(() => {
        virgilCrypto.generateGroupSession('short_id');
      }, 'should have thrown').throws(Error);
    });

    it('creates group with correct id', () => {
      const expectedId = virgilCrypto
        .calculateHash('i_am_long_enough_to_be_a_group_id', HashAlgorithm.SHA512)
        .slice(0, 32);
      const group = virgilCrypto.generateGroupSession('i_am_long_enough_to_be_a_group_id');
      expect(group.getSessionId()).to.equal(expectedId.toString('hex'));
    });

    it('creates group with one epoch', () => {
      const group = virgilCrypto.generateGroupSession('i_am_long_enough_to_be_a_group_id');
      expect(group.export()).to.have.length(1);
    });
  });

  describe('importGroupSession', () => {
    it('throws if epoch messages is not an array', () => {
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        virgilCrypto.importGroupSession(undefined as any);
      }).throws(TypeError);
    });

    it('throws if epoch messages array is empty', () => {
      expect(() => {
        virgilCrypto.importGroupSession([]);
      }).throws(Error);
    });

    it('reconstructs the group session object from epoch messages', () => {
      const myGroup = virgilCrypto.generateGroupSession(NodeBuffer.from('x'.repeat(10)));
      myGroup.addNewEpoch();
      const epochMessages = myGroup.export();
      const theirGroup = virgilCrypto.importGroupSession(epochMessages);

      expect(myGroup.getSessionId()).to.equal(theirGroup.getSessionId());
      expect(myGroup.getCurrentEpochNumber()).to.equal(theirGroup.getCurrentEpochNumber());
    });
  });

  describe('calculateGroupSessionId', () => {
    it('throws if groupId is less than 10 bytes long', () => {
      expect(() => {
        virgilCrypto.calculateGroupSessionId('short_id');
      }, 'should have thrown').throws(Error);
    });

    it('returns correct as hex string', () => {
      const expectedId = virgilCrypto
        .calculateHash('i_am_long_enough_to_be_a_group_id', HashAlgorithm.SHA512)
        .slice(0, 32);
      const groupSessionId = virgilCrypto.calculateGroupSessionId(
        'i_am_long_enough_to_be_a_group_id',
      );
      expect(groupSessionId).to.equal(expectedId.toString('hex'));
    });
  });
});
