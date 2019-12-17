import { getFoundationModules } from './foundationModules';
import { FoundationModules, IPublicKey } from './types';

export class VirgilPublicKey implements IPublicKey {
  public readonly identifier: Uint8Array;
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
    this.identifier = identifier;
    this.lowLevelPublicKey = lowLevelPublicKey;
    this._isDisposed = false;
  }

  dispose() {
    this.lowLevelPublicKey.delete();
    this._isDisposed = true;
  }
}
