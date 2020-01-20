import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { PADDING_LEN } from './constants';
import { getFoundationModules } from './foundationModules';
import { getRandom } from './globalInstances';
import { FoundationModules, Data } from './types';
import { toArray } from './utils';
import { validatePrivateKey, validatePublicKeysArray } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export class VirgilStreamDecryptAndVerify {
  private _isDisposed: boolean;
  private _isFinished: boolean;

  private readonly paddingParams: FoundationModules.PaddingParams;
  private readonly recipientCipher: FoundationModules.RecipientCipher;

  constructor() {
    const foundation = getFoundationModules();
    this.paddingParams = foundation.PaddingParams.newWithConstraints(PADDING_LEN, PADDING_LEN);
    this.recipientCipher = new foundation.RecipientCipher();
    this.recipientCipher.random = getRandom();
    this.recipientCipher.paddingParams = this.paddingParams;
    this._isDisposed = false;
    this._isFinished = false;
  }

  start(privateKey: VirgilPrivateKey) {
    this.ensureLegalState();
    validatePrivateKey(privateKey);
    this.recipientCipher.startDecryptionWithKey(
      privateKey.identifier,
      privateKey.lowLevelPrivateKey,
      new Uint8Array(),
    );
  }

  update(data: Data) {
    this.ensureLegalState();
    const myData = dataToUint8Array(data);
    const processEncryption = this.recipientCipher.processDecryption(myData);
    return toBuffer(processEncryption);
  }

  final() {
    this.ensureLegalState();
    const finishDecryption = this.recipientCipher.finishDecryption();
    try {
      return toBuffer(finishDecryption);
    } finally {
      this._isFinished = true;
    }
  }

  verify(publicKey: VirgilPublicKey, dispose?: boolean): void;
  verify(publicKeys: VirgilPublicKey[], dispose?: boolean): void;
  verify(arg0: VirgilPublicKey | VirgilPublicKey[], arg1 = true) {
    const publicKeys = toArray(arg0);
    validatePublicKeysArray(publicKeys);
    if (this._isDisposed) {
      throw new Error(
        'Illegal state. Cannot verify signature after the `dispose` method has been called.',
      );
    }
    if (!this._isFinished) {
      throw new Error(
        'Illegal state. Cannot verify signature before the `final` method has been called.',
      );
    }
    let signerInfo: FoundationModules.SignerInfo | undefined;
    let signerInfoList: FoundationModules.SignerInfoList | undefined;
    try {
      if (!this.recipientCipher.isDataSigned()) {
        throw new Error('Data is not signed');
      }
      signerInfoList = this.recipientCipher.signerInfos();
      if (!signerInfoList.hasItem()) {
        throw new Error('Data is not signed');
      }
      const signerInfo = signerInfoList.item();
      let signerPublicKey: VirgilPublicKey;
      for (let i = 0; i < publicKeys.length; i += 1) {
        if (NodeBuffer.compare(signerInfo.signerId(), publicKeys[i].identifier) === 0) {
          signerPublicKey = publicKeys[i];
          break;
        }
        if (i === publicKeys.length - 1) {
          throw new Error('Signer not found');
        }
      }
      if (!this.recipientCipher.verifySignerInfo(signerInfo, signerPublicKey!.lowLevelPublicKey)) {
        throw new Error('Invalid signature');
      }
    } finally {
      if (signerInfo) {
        signerInfo.delete();
      }
      if (signerInfoList) {
        signerInfoList.delete();
      }
      if (arg1) {
        this.dispose();
      }
    }
  }

  dispose() {
    this.paddingParams.delete();
    this.recipientCipher.delete();
    this._isDisposed = true;
  }

  private ensureLegalState() {
    if (this._isDisposed) {
      throw new Error(
        'Illegal state. Cannot use cipher after the `dispose` method has been called.',
      );
    }
    if (this._isFinished) {
      throw new Error('Illegal state. Cannot use cipher after the `final` method has been called.');
    }
  }
}
