import { IPublicKey } from './interfaces';
import { LowLevelPublicKey } from './types';

export class VirgilPublicKey implements IPublicKey {
  public identifier: Uint8Array;

  public key: LowLevelPublicKey;

  public constructor(identifier: Uint8Array, key: LowLevelPublicKey) {
    this.identifier = identifier;
    this.key = key;
  }
}
