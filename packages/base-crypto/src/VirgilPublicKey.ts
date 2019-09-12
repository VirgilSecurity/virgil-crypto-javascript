import { serializePublicKey } from './keySerializer';
import { IPublicKey, LowLevelPublicKey } from './types';

export class VirgilPublicKey implements IPublicKey {
  public identifier: Uint8Array;

  public key: Uint8Array;

  public constructor(identifier: Uint8Array, key: LowLevelPublicKey) {
    this.identifier = identifier;
    this.key = serializePublicKey(key);
  }
}
