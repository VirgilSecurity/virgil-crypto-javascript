import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPheModules } from './pheModules';
import { PheModules, Data, IPheClient } from './types';

export class PheClient implements IPheClient {
  private readonly pheModules: PheModules;
  private readonly pheClient: any;

  private disposed: boolean;

  constructor() {
    this.pheModules = getPheModules();
    this.pheClient = new this.pheModules.PheClient();
    try {
      this.pheClient.setupDefaults();
      this.disposed = false;
    } catch (error) {
      this.dispose();
      throw error;
    }
  }

  dispose() {
    this.pheClient.delete();
    this.disposed = true;
  }

  setKeys(clientPrivateKey: Data, serverPublicKey: Data) {
    this.throwIfDisposed();
    const myClientPrivateKey = dataToUint8Array(clientPrivateKey, 'base64');
    const myServerPublicKey = dataToUint8Array(serverPublicKey, 'base64');
    this.pheClient.setKeys(myClientPrivateKey, myServerPublicKey);
  }

  generateClientPrivateKey() {
    this.throwIfDisposed();
    const clientPrivateKey = this.pheClient.generateClientPrivateKey();
    return toBuffer(clientPrivateKey);
  }

  enrollAccount(enrollmentResponse: Data, password: Data) {
    this.throwIfDisposed();
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
    this.throwIfDisposed();
    const myPassword = dataToUint8Array(password, 'utf8');
    const myEnrollmentRecord = dataToUint8Array(enrollmentRecord, 'base64');
    const verifyPasswordRequest = this.pheClient.createVerifyPasswordRequest(
      myPassword,
      myEnrollmentRecord,
    );
    return toBuffer(verifyPasswordRequest);
  }

  checkResponseAndDecrypt(password: Data, enrollmentRecord: Data, verifyPasswordResponse: Data) {
    this.throwIfDisposed();
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
    this.throwIfDisposed();
    const myUpdateToken = dataToUint8Array(updateToken, 'base64');
    const { newClientPrivateKey, newServerPublicKey } = this.pheClient.rotateKeys(myUpdateToken);
    return {
      newClientPrivateKey: toBuffer(newClientPrivateKey),
      newServerPublicKey: toBuffer(newServerPublicKey),
    };
  }

  updateEnrollmentRecord(enrollmentRecord: Data, updateToken: Data) {
    this.throwIfDisposed();
    const myEnrollmentRecord = dataToUint8Array(enrollmentRecord, 'base64');
    const myUpdateToken = dataToUint8Array(updateToken, 'base64');
    const newEnrollmentRecord = this.pheClient.updateEnrollmentRecord(
      myEnrollmentRecord,
      myUpdateToken,
    );
    return toBuffer(newEnrollmentRecord);
  }

  private throwIfDisposed() {
    if (this.disposed) {
      throw new Error(
        'Cannot use an instance of `PheClient` class after the `dispose` method has been called',
      );
    }
  }
}
