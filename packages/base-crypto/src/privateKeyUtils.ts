import { importPrivateKey } from './keyProvider';
import { serializePrivateKey } from './keySerializer';
import { LowLevelPrivateKey } from './types';
import { VirgilPrivateKey } from './VirgilPrivateKey';

const privateKeys = new WeakMap();
const setValue = WeakMap.prototype.set;
const getValue = WeakMap.prototype.get;
const hasValue = WeakMap.prototype.has;

export function getLowLevelPrivateKey(privateKey: VirgilPrivateKey): LowLevelPrivateKey {
  const serializedPrivateKey = getValue.call(privateKeys, privateKey);
  return importPrivateKey(serializedPrivateKey);
}

export function setLowLevelPrivateKey(
  privateKey: VirgilPrivateKey,
  lowLevelPrivateKey: LowLevelPrivateKey,
): void {
  const serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
  setValue.call(privateKeys, privateKey, serializedPrivateKey);
}

export function hasLowLevelPrivateKey(privateKey: VirgilPrivateKey): boolean {
  return hasValue.call(privateKeys, privateKey);
}
