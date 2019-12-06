import { IPrivateKey } from './types';

export class VirgilPrivateKey implements IPrivateKey {
  public readonly identifier: Uint8Array;
  public readonly lowLevelPrivateKey: FoundationModules.PrivateKey;

  private _isDisposed: boolean;

  get isDisposed() {
    return this._isDisposed;
  }

  constructor(indentifier: Uint8Array, lowLevelPrivateKey: FoundationModules.PrivateKey) {
    this.identifier = indentifier;
    this.lowLevelPrivateKey = lowLevelPrivateKey;
    this._isDisposed = false;
  }

  dispose() {
    this.lowLevelPrivateKey.delete();
    this._isDisposed = true;
  }
}
