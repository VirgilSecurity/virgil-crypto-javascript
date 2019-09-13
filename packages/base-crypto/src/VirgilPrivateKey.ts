import { setLowLevelPrivateKey } from './privateKeyUtils';
import { IPrivateKey } from './types';

export class VirgilPrivateKey implements IPrivateKey {
  public identifier: Uint8Array;

  public constructor(indentifier: Uint8Array, key: Uint8Array) {
    this.identifier = indentifier;
    setLowLevelPrivateKey(this, key);
  }
}
