import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPheModules } from './pheModules';
import { PheModules, Data, IPheClient } from './types';

export class PheClient implements IPheClient {
  private readonly pheModules: PheModules;
  private readonly random: any;
  private readonly pheClient: any;

  constructor() {
    this.pheModules = getPheModules();
    this.random = new this.pheModules.CtrDrbg();
    this.pheClient = new this.pheModules.PheClient();
    this.pheClient.random = this.random;
    try {
      this.pheClient.setupDefaults();
    } finally {
      this.dispose();
    }
  }

  dispose() {
    this.pheClient.delete();
    this.random.delete();
  }

  setKeys(clientPrivateKey: Data, serverPublicKey: Data) {
    const myClientPrivateKey = dataToUint8Array(clientPrivateKey, 'base64');
    const myServerPublicKey = dataToUint8Array(serverPublicKey, 'base64');
    this.pheClient.setKeys(myClientPrivateKey, myServerPublicKey);
  }

  generateClientPrivateKey() {
    const clientPrivateKey = this.pheClient.generateClientPrivateKey();
    return toBuffer(clientPrivateKey);
  }

  enrollAccount(enrollmentResponse: Data, password: Data) {
    const myEnrollmentResponse = dataToUint8Array(enrollmentResponse, 'base64');
    const myPassword = dataToUint8Array(password, 'utf8');
    const { enrollmentRecord, accountKey } = this.pheClient.enrollAccount(
      myEnrollmentResponse,
      myPassword,
    );
    return {
      enrollmentRecord: toBuffer(enrollmentRecord),
      accountKey: toBuffer(accountKey),
    };
  }

  createVerifyPasswordRequest(password: Data, enrollmentRecord: Data) {
    const myPassword = dataToUint8Array(password, 'utf8');
    const myEnrollmentRecord = dataToUint8Array(enrollmentRecord, 'base64');
    const verifyPasswordRequest = this.pheClient.createVerifyPasswordRequest(
      myPassword,
      myEnrollmentRecord,
    );
    return toBuffer(verifyPasswordRequest);
  }

  checkResponseAndDecrypt(password: Data, enrollmentRecord: Data, verifyPasswordResponse: Data) {
    const myPassword = dataToUint8Array(password, 'utf8');
    const myEnrollmentRecord = dataToUint8Array(enrollmentRecord, 'base64');
    const myVerifyPasswordResponse = dataToUint8Array(verifyPasswordResponse, 'base64');
    const accountKey = this.pheClient.checkResponseAndDecrypt(
      myPassword,
      myEnrollmentRecord,
      myVerifyPasswordResponse,
    );
    return toBuffer(accountKey);
  }

  rotateKeys(updateToken: Data) {
    const myUpdateToken = dataToUint8Array(updateToken, 'base64');
    const { newClientPrivateKey, newServerPublicKey } = this.pheClient.rotateKeys(myUpdateToken);
    return {
      newClientPrivateKey: toBuffer(newClientPrivateKey),
      newServerPublicKey: toBuffer(newServerPublicKey),
    };
  }

  updateEnrollmentRecord(enrollmentRecord: Data, updateToken: Data) {
    const myEnrollmentRecord = dataToUint8Array(enrollmentRecord, 'base64');
    const myUpdateToken = dataToUint8Array(updateToken, 'base64');
    const newEnrollmentRecord = this.pheClient.updateEnrollmentRecord(
      myEnrollmentRecord,
      myUpdateToken,
    );
    return toBuffer(newEnrollmentRecord);
  }
}
