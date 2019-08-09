import { LowLevelPrivateKey } from './types';
import { VirgilPrivateKey } from './VirgilPrivateKey';

const privateKeys = new WeakMap();
const setValue = WeakMap.prototype.set;
const getValue = WeakMap.prototype.get;
const hasValue = WeakMap.prototype.has;

export function getLowLevelPrivateKey(privateKey: VirgilPrivateKey): LowLevelPrivateKey {
  return getValue.call(privateKeys, privateKey);
}

export function setLowLevelPrivateKey(
  privateKey: VirgilPrivateKey,
  lowLevelPrivateKey: LowLevelPrivateKey,
): void {
  setValue.call(privateKeys, privateKey, lowLevelPrivateKey);
}

export function hasLowLevelPrivateKey(privateKey: VirgilPrivateKey): boolean {
  return hasValue.call(privateKeys, privateKey);
}
