import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getPheModules } from './pheModules';
import { PheModules, Data, IPheServer } from './types';

export class PheServer implements IPheServer {
  private readonly pheModules: PheModules;
  private readonly random: any;
  private readonly pheServer: any;

  constructor() {
    this.pheModules = getPheModules();
    this.random = new this.pheModules.CtrDrbg();
    this.pheServer = new this.pheModules.PheServer();
    this.pheServer.random = this.random;
    try {
      this.pheServer.setupDefaults();
    } finally {
      this.disponse();
    }
  }

  disponse() {
    this.pheServer.delete();
    this.random.delete();
  }

  generateServerKeyPair() {
    const { serverPrivateKey, serverPublicKey } = this.pheServer.generateServerKeyPair();
    return {
      serverPrivateKey: toBuffer(serverPrivateKey),
      serverPublicKey: toBuffer(serverPublicKey),
    };
  }

  getEnrollment(serverPrivateKey: Data, serverPublicKey: Data) {
    const myServerPrivateKey = dataToUint8Array(serverPrivateKey, 'base64');
    const myServerPublicKey = dataToUint8Array(serverPublicKey, 'base64');
    const enrollmentResponse = this.pheServer.getEnrollment(myServerPrivateKey, myServerPublicKey);
    return toBuffer(enrollmentResponse);
  }

  verifyPassword(serverPrivateKey: Data, serverPublicKey: Data, verifyPasswordRequest: Data) {
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
}
