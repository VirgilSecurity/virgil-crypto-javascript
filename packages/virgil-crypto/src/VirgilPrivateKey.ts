import { toBuffer } from '@virgilsecurity/data-utils';

import { IPrivateKey, NodeBuffer } from './types';

export class VirgilPrivateKey implements IPrivateKey {
  public readonly identifier: NodeBuffer;
  public readonly lowLevelPrivateKey: FoundationModules.PrivateKey;

  private _isDisposed: boolean;

  get isDisposed() {
    return this._isDisposed;
  }

  constructor(indentifier: Uint8Array, lowLevelPrivateKey: FoundationModules.PrivateKey) {
    this.identifier = toBuffer(indentifier);
    this.lowLevelPrivateKey = lowLevelPrivateKey;
    this._isDisposed = false;
  }

  dispose() {
    this.lowLevelPrivateKey.delete();
    this._isDisposed = true;
  }
}
