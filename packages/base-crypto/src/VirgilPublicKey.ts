import { IPublicKey } from './types';

export class VirgilPublicKey implements IPublicKey {
  public identifier: Uint8Array;

  public key: Uint8Array;

  public constructor(identifier: Uint8Array, key: Uint8Array) {
    this.identifier = identifier;
    this.key = key;
  }
}
