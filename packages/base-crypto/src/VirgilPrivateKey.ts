import { IPrivateKey } from './interfaces';
import { setLowLevelPrivateKey } from './privateKeyUtils';
import { LowLevelPrivateKey } from './types';

export class VirgilPrivateKey implements IPrivateKey {
  public identifier: Uint8Array;

  public constructor(indentifier: Uint8Array, lowLevelPrivateKey: LowLevelPrivateKey) {
    this.identifier = indentifier;
    setLowLevelPrivateKey(this, lowLevelPrivateKey);
  }
}
