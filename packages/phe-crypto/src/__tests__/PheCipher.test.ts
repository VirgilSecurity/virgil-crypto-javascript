import { expect } from 'chai';
import { NodeBuffer } from '@virgilsecurity/data-utils';

import { initPhe } from '../initPhe';
import { PheCipher } from '../PheCipher';
import { PheClient } from '../PheClient';
import { PheServer } from '../PheServer';

type Data = import('@virgilsecurity/crypto-types').Data;

describe('PheCipher', () => {
  let pheCipher: PheCipher;
  let pheClient: PheClient;
  let pheServer: PheServer;

  before(async () => {
    await initPhe();
  });

  beforeEach(() => {
    pheCipher = new PheCipher();
    pheClient = new PheClient();
    pheServer = new PheServer();
  });

  const getKeys = () => {
    const { serverPrivateKey, serverPublicKey } = pheServer.generateServerKeyPair();
    const clientPrivateKey = pheClient.generateClientPrivateKey();
    return { clientPrivateKey, serverPrivateKey, serverPublicKey };
  };

  const enrollAccount = (password: Data, serverPrivateKey: Data, serverPublicKey: Data) => {
    const enrollment = pheServer.getEnrollment(serverPrivateKey, serverPublicKey);
    return pheClient.enrollAccount(enrollment, password);
  };

  describe('encrypt', () => {
    it('returns cipher text', () => {
      const data = 'text';
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const cipherText = pheCipher.encrypt(data, accountKey);
      expect(NodeBuffer.isBuffer(cipherText)).to.be.true;
    });

    it('throws if was disposed', () => {
      const data = 'text';
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      pheCipher.dispose();
      const error = () => pheCipher.encrypt(data, accountKey);
      expect(error).to.throw;
    });
  });

  describe('decrypt', () => {
    it('returns plain text', () => {
      const data = 'text';
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const cipherText = pheCipher.encrypt(data, accountKey);
      const plainText = pheCipher.decrypt(cipherText, accountKey);
      expect(plainText.toString()).to.equal(data);
    });

    it('throws if was disposed', () => {
      const data = 'text';
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const cipherText = pheCipher.encrypt(data, accountKey);
      pheCipher.dispose();
      const error = () => pheCipher.decrypt(cipherText, accountKey);
      expect(error).to.throw;
    });
  });

  describe('authEncrypt', () => {
    it('returns cipher text', () => {
      const data = 'text';
      const additionalData: Data = { value: 'additionalData', encoding: 'utf8' };
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const cipherText = pheCipher.authEncrypt(data, additionalData, accountKey);
      expect(NodeBuffer.isBuffer(cipherText)).to.be.true;
    });

    it('throws if was disposed', () => {
      const data = 'text';
      const additionalData: Data = { value: 'additionalData', encoding: 'utf8' };
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      pheCipher.dispose();
      const error = () => pheCipher.authEncrypt(data, additionalData, accountKey);
      expect(error).to.throw;
    });
  });

  describe('authDecrypt', () => {
    it('returns plain text', () => {
      const data = 'text';
      const additionalData: Data = { value: 'additionalData', encoding: 'utf8' };
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const cipherText = pheCipher.authEncrypt(data, additionalData, accountKey);
      const plainText = pheCipher.authDecrypt(cipherText, additionalData, accountKey);
      expect(plainText.toString()).to.equal(data);
    });

    it('throws if was disposed', () => {
      const data = 'text';
      const additionalData: Data = { value: 'additionalData', encoding: 'utf8' };
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { accountKey } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const cipherText = pheCipher.authEncrypt(data, additionalData, accountKey);
      pheCipher.dispose();
      const error = () => pheCipher.authDecrypt(cipherText, additionalData, accountKey);
      expect(error).to.throw;
    });
  });
});
