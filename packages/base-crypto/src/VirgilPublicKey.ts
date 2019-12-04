import { IPublicKey } from './types';

export class VirgilPublicKey implements IPublicKey {
  public readonly identifier: Uint8Array;
  public readonly lowLevelPublicKey: FoundationModules.PublicKey;

  private _isDisposed: boolean;

  get isDisposed() {
    return this._isDisposed;
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
