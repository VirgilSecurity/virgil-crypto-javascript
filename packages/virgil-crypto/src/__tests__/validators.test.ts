import { expect } from 'chai';

import { MIN_GROUP_ID_BYTE_LENGTH } from '../constants';
import { initCrypto } from '../foundationModules';
import {
  validatePrivateKey,
  validatePublicKey,
  validatePublicKeysArray,
  validatePositiveNonZeroNumber,
  validateGroupId,
} from '../validators';
import { VirgilCrypto } from '../VirgilCrypto';

describe('validators', () => {
  let virgilCrypto: VirgilCrypto;

  before(async () => {
    await initCrypto();
  });

  beforeEach(() => {
    virgilCrypto = new VirgilCrypto();
  });

  describe('validatePrivateKey', () => {
    it('returns if argument is instance of VirgilPrivateKey class', () => {
      const { privateKey } = virgilCrypto.generateKeys();
      const func = () => {
        validatePrivateKey(privateKey);
      };
      expect(func).not.to.throw(TypeError);
    });

    it('throws if argument is not an instance of VirgilPrivateKey class', () => {
      const { publicKey } = virgilCrypto.generateKeys();
      const error = () => {
        validatePrivateKey(publicKey);
      };
      expect(error).to.throw(TypeError);
    });

    it('throws if VirgilPrivateKey instance was disposed', () => {
      const { privateKey } = virgilCrypto.generateKeys();
      privateKey.dispose();
      const error = () => {
        validatePrivateKey(privateKey);
      };
      expect(error).to.throw(TypeError);
    });
  });

  describe('validatePublicKey', () => {
    it('returns if argument is instance of VirgilPublicKey class', () => {
      const { publicKey } = virgilCrypto.generateKeys();
      const func = () => {
        validatePublicKey(publicKey);
      };
      expect(func).not.to.throw(TypeError);
    });

    it('throws if argument is not an instance of VirgilPublicKey class', () => {
      const { privateKey } = virgilCrypto.generateKeys();
      const error = () => {
        validatePublicKey(privateKey);
      };
      expect(error).to.throw(TypeError);
    });

    it('throws if VirgilPrivateKey instance was disposed', () => {
      const { publicKey } = virgilCrypto.generateKeys();
      publicKey.dispose();
      const error = () => {
        validatePublicKey(publicKey);
      };
      expect(error).to.throw(TypeError);
    });
  });

  describe('validatePublicKeysArray', () => {
    it('returns if argument is an array of VirgilPublicKey instances', () => {
      const { publicKey: publicKey1 } = virgilCrypto.generateKeys();
      const { publicKey: publicKey2 } = virgilCrypto.generateKeys();
      const func = () => {
        validatePublicKeysArray([publicKey1, publicKey2]);
      };
      expect(func).not.to.throw(TypeError);
    });

    it('throws if argument is not an array of VirgilPublicKey instances', () => {
      const { publicKey } = virgilCrypto.generateKeys();
      const { privateKey } = virgilCrypto.generateKeys();
      const error = () => {
        validatePublicKeysArray([publicKey, privateKey]);
      };
      expect(error).to.throw(TypeError);
    });

    it('throws if array of VirgilPublicKey instances is emtpy', () => {
      const error = () => {
        validatePublicKeysArray([]);
      };
      expect(error).to.throw(TypeError);
    });

    it('throws if disposed', () => {
      const { publicKey: publicKey1 } = virgilCrypto.generateKeys();
      const { publicKey: publicKey2 } = virgilCrypto.generateKeys();
      publicKey2.dispose();
      const error = () => {
        validatePublicKeysArray([publicKey1, publicKey2]);
      };
      expect(error).to.throw(TypeError);
    });
  });

  describe('validatePositiveNonZeroNumber', () => {
    it('returns if argument is number', () => {
      const func = () => {
        validatePositiveNonZeroNumber(777);
      };
      expect(func).not.to.throw(TypeError);
    });

    it('throws if arugment is not a number', () => {
      const error = () => {
        validatePositiveNonZeroNumber({});
      };
      expect(error).to.throw(TypeError);
    });

    it('throws if argument is less or equal to 0', () => {
      const error = () => {
        validatePositiveNonZeroNumber(0);
      };
      expect(error).to.throw(TypeError);
    });
  });

  describe('validateGroupId', () => {
    it('returns if argument is instance of Uint8Array class and has proper byte length', () => {
      const func = () => {
        validateGroupId(new Uint8Array(MIN_GROUP_ID_BYTE_LENGTH));
      };
      expect(func).not.to.throw;
    });

    it('throws if argument is not an instance of Uint8Array class', () => {
      const error = () => {
        validateGroupId({});
      };
      expect(error).to.throw(TypeError);
    });

    it("throws if argument's byte length is too small", () => {
      const error = () => {
        validateGroupId(new Uint8Array(MIN_GROUP_ID_BYTE_LENGTH - 1));
      };
      expect(error).to.throw(TypeError);
    });
  });
});
