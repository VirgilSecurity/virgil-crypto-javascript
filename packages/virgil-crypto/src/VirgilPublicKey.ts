import { toBuffer } from '@virgilsecurity/data-utils';

import { getFoundationModules } from './foundationModules';
import { FoundationModules, IPublicKey, NodeBuffer } from './types';

export class VirgilPublicKey implements IPublicKey {
  public readonly identifier: NodeBuffer;
  public readonly lowLevelPublicKey: FoundationModules.PublicKey;

  private _isDisposed: boolean;

  get isDisposed() {
    return this._isDisposed;
  }

  get key() {
    const foundationModules = getFoundationModules();
    const keyAsn1Serializer = new foundationModules.KeyAsn1Serializer();
    try {
      keyAsn1Serializer.setupDefaults();
      return keyAsn1Serializer.serializePublicKey(this.lowLevelPublicKey);
    } finally {
      keyAsn1Serializer.delete();
    }
  }

  constructor(identifier: Uint8Array, lowLevelPublicKey: FoundationModules.PublicKey) {
    this.identifier = toBuffer(identifier);
    this.lowLevelPublicKey = lowLevelPublicKey;
    this._isDisposed = false;
  }

  dispose() {
    this.lowLevelPublicKey.delete();
    this._isDisposed = true;
  }
}
