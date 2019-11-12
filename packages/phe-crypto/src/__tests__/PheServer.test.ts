import { expect } from 'chai';
import { NodeBuffer } from '@virgilsecurity/data-utils';

import { initPhe } from '../initPhe';
import { PheClient } from '../PheClient';
import { PheServer } from '../PheServer';

type Data = import('@virgilsecurity/crypto-types').Data;

describe('PheServer', () => {
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

  describe('generateServerKeyPair', () => {
    it('returns server private key and server public key', () => {
      const result = pheServer.generateServerKeyPair();
      expect(result).to.have.keys(['serverPrivateKey', 'serverPublicKey']);
      expect(NodeBuffer.isBuffer(result.serverPrivateKey)).to.be.true;
      expect(NodeBuffer.isBuffer(result.serverPublicKey)).to.be.true;
    });
  });

  describe('getEnrollment', () => {
    it('returns enrollment', () => {
      const { serverPrivateKey, serverPublicKey } = pheServer.generateServerKeyPair();
      const enrollment = pheServer.getEnrollment(serverPrivateKey, serverPublicKey);
      expect(NodeBuffer.isBuffer(enrollment)).to.be.true;
    });
  });

  describe('verifyPassword', () => {
    it('returns verify password response', () => {
      const password = 'password';
      const { clientPrivateKey, serverPrivateKey, serverPublicKey } = getKeys();
      pheClient.setKeys(clientPrivateKey, serverPublicKey);
      const { enrollmentRecord } = enrollAccount(password, serverPrivateKey, serverPublicKey);
      const verifyPasswordRequest = pheClient.createVerifyPasswordRequest(
        password,
        enrollmentRecord,
      );
      const verifyPasswordResponse = pheServer.verifyPassword(
        serverPrivateKey,
        serverPublicKey,
        verifyPasswordRequest,
      );
      expect(NodeBuffer.isBuffer(verifyPasswordResponse)).to.be.true;
    });
  });

  describe('rotateKeys', () => {
    it('returns new server private key, new server public key and update token', () => {
      const { serverPrivateKey } = pheServer.generateServerKeyPair();
      const result = pheServer.rotateKeys(serverPrivateKey);
      expect(result).to.have.keys(['newServerPrivateKey', 'newServerPublicKey', 'updateToken']);
      expect(NodeBuffer.isBuffer(result.newServerPrivateKey)).to.be.true;
      expect(NodeBuffer.isBuffer(result.newServerPublicKey)).to.be.true;
      expect(NodeBuffer.isBuffer(result.updateToken)).to.be.true;
    });
  });
});
