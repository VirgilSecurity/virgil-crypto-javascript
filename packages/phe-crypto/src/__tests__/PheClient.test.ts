import { expect } from 'chai';
import { NodeBuffer } from '@virgilsecurity/data-utils';

import { initPhe } from '../initPhe';
import { PheClient } from '../PheClient';
import { PheServer } from '../PheServer';

type Data = import('@virgilsecurity/crypto-types').Data;

describe('PheClient', () => {
  let pheClient: PheClient;
  let pheServer: PheServer;

  before(async () => {
    await initPhe();
  });

  beforeEach(() => {
    pheClient = new PheClient();
    pheServer = new PheServer();
  });

  afterEach(() => {
    pheClient.dispose();
    pheServer.dispose();
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

  const verifyPassword = (
    password: Data,
    enrollmentRecord: Data,
    serverPrivateKey: Data,
    serverPublicKey: Data,
  ) => {
    const verifyPasswordRequest = pheClient.createVerifyPasswordRequest(password, enrollmentRecord);
    return pheServer.verifyPassword(serverPrivateKey, serverPublicKey, verifyPasswordRequest);
  };

  describe('setKeys', () => {
    it('sets keys', () => {
      const { clientPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
    });

    it('throws if was disposed', () => {
      const { clientPrivateKey, serverPublicKey } = getKeys();
      pheClient.dispose();
      const error = () => pheClient.setKeys(clientPrivateKey, serverPublicKey);
      expect(error).to.throw;
    });
  });

  describe('generateClientPrivateKey', () => {
    it('returns client private key', () => {
      const clientPrivateKey = pheClient.generateClientPrivateKey();
      expect(NodeBuffer.isBuffer(clientPrivateKey)).to.be.true;
    });

    it('throws if was disposed', () => {
      pheClient.dispose();
      const error = () => pheClient.generateClientPrivateKey();
      expect(error).to.throw;
    });
  });

  describe('enrollAccount', () => {
    it('returns enrollment record and account key', () => {
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const enrollment = pheServer.getEnrollment(serverPrivateKey, serverPublicKey);
      const result = pheClient.enrollAccount(enrollment, password);
      expect(result).to.have.keys(['enrollmentRecord', 'accountKey']);
      expect(NodeBuffer.isBuffer(result.enrollmentRecord)).to.be.true;
      expect(NodeBuffer.isBuffer(result.accountKey)).to.be.true;
    });

    it('throws if was disposed', () => {
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const enrollment = pheServer.getEnrollment(serverPrivateKey, serverPublicKey);
      const error = () => pheClient.enrollAccount(enrollment, password);
      expect(error).to.throw;
    });
  });

  describe('createVerifyPasswordRequest', () => {
    it('returns verify password request', () => {
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { enrollmentRecord } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const verifyPasswordRequest = pheClient.createVerifyPasswordRequest(
        'password',
        enrollmentRecord,
      );
      expect(NodeBuffer.isBuffer(verifyPasswordRequest)).to.be.true;
    });

    it('throws if was disposed', () => {
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { enrollmentRecord } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const error = () => pheClient.createVerifyPasswordRequest('password', enrollmentRecord);
      expect(error).to.throw;
    });
  });

  describe('checkResponseAndDecrypt', () => {
    it('returns account key', () => {
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { enrollmentRecord, accountKey } = enrollAccount(
        password,
        serverPrivateKey,
        serverPublicKey,
      );
      const verifyPasswordResponse = verifyPassword(
        password,
        enrollmentRecord,
        serverPrivateKey,
        serverPublicKey,
      );
      const decryptedAccountKey = pheClient.checkResponseAndDecrypt(
        password,
        enrollmentRecord,
        verifyPasswordResponse,
      );
      expect(decryptedAccountKey.equals(accountKey)).to.be.true;
    });
  });

  describe('rotateKeys', () => {
    it('returns new client private key and new server public key', () => {
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { updateToken } = pheServer.rotateKeys(serverPrivateKey);
      const result = pheClient.rotateKeys(updateToken);
      expect(result).to.have.keys(['newClientPrivateKey', 'newServerPublicKey']);
      expect(NodeBuffer.isBuffer(result.newClientPrivateKey)).to.be.true;
      expect(NodeBuffer.isBuffer(result.newServerPublicKey)).to.be.true;
    });
  });

  describe('updateEnrollmentRecord', () => {
    it('returns new enrollment record', () => {
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { enrollmentRecord } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const { updateToken } = pheServer.rotateKeys(serverPrivateKey);
      const newEnrollmentRecord = pheClient.updateEnrollmentRecord(enrollmentRecord, updateToken);
      expect(NodeBuffer.isBuffer(newEnrollmentRecord)).to.be.true;
    });
  });
});
