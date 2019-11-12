import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPheModules } from './pheModules';
import { PheModules, Data, IPheServer } from './types';

export class PheServer implements IPheServer {
  private readonly pheModules: PheModules;
  private readonly pheServer: any;

  private disposed: boolean;

  constructor() {
    this.pheModules = getPheModules();
    this.pheServer = new this.pheModules.PheServer();
    try {
      this.pheServer.setupDefaults();
      this.disposed = false;
    } catch (error) {
      this.dispose();
      throw error;
    }
  }

  dispose() {
    this.pheServer.delete();
    this.disposed = true;
  }

  generateServerKeyPair() {
    this.throwIfDisposed();
    const { serverPrivateKey, serverPublicKey } = this.pheServer.generateServerKeyPair();
    return {
      serverPrivateKey: toBuffer(serverPrivateKey),
      serverPublicKey: toBuffer(serverPublicKey),
    };
  }

  getEnrollment(serverPrivateKey: Data, serverPublicKey: Data) {
    this.throwIfDisposed();
    const myServerPrivateKey = dataToUint8Array(serverPrivateKey, 'base64');
    const myServerPublicKey = dataToUint8Array(serverPublicKey, 'base64');
    const enrollmentResponse = this.pheServer.getEnrollment(myServerPrivateKey, myServerPublicKey);
    return toBuffer(enrollmentResponse);
  }

  verifyPassword(serverPrivateKey: Data, serverPublicKey: Data, verifyPasswordRequest: Data) {
    this.throwIfDisposed();
    const myServerPrivateKey = dataToUint8Array(serverPrivateKey, 'base64');
    const myServerPublicKey = dataToUint8Array(serverPublicKey, 'base64');
    const myVerifyPasswordRequest = dataToUint8Array(verifyPasswordRequest, 'base64');
    const verifyPasswordResponse = this.pheServer.verifyPassword(
      myServerPrivateKey,
      myServerPublicKey,
      myVerifyPasswordRequest,
    );
    return toBuffer(verifyPasswordResponse);
  }

  rotateKeys(serverPrivateKey: Data) {
    this.throwIfDisposed();
    const myServerPrivateKey = dataToUint8Array(serverPrivateKey, 'base64');
    const { newServerPrivateKey, newServerPublicKey, updateToken } = this.pheServer.rotateKeys(
      myServerPrivateKey,
    );
    return {
      newServerPrivateKey: toBuffer(newServerPrivateKey),
      newServerPublicKey: toBuffer(newServerPublicKey),
      updateToken: toBuffer(updateToken),
    };
  }

  private throwIfDisposed() {
    if (this.disposed) {
      throw new Error(
        'Cannot use an instance of `PheServer` class after the `dispose` method has been called',
      );
    }
  }
}
