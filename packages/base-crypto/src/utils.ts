import { importPublicKey } from './keyProvider';
import { LowLevelPublicKey } from './types';
import { VirgilPublicKey } from './VirgilPublicKey';

export const toArray = <T>(val?: T | T[]): T[] => {
  return val == null ? [] : Array.isArray(val) ? val : [val];
};

export const getLowLevelPublicKeys = (publicKeys: VirgilPublicKey[]) => {
  const lowLevelPublicKeys: LowLevelPublicKey[] = [];
  publicKeys.forEach(({ key }) => {
    try {
      const lowLevelPublicKey = importPublicKey(key);
      lowLevelPublicKeys.push(lowLevelPublicKey);
    } catch (error) {
      lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
      throw error;
    }
  });
  return lowLevelPublicKeys;
};
