import { FoundationModules, getFoundationModules } from './foundationModules';

export interface HashAlgorithmType {
  SHA224: number;
  SHA256: number;
  SHA384: number;
  SHA512: number;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const addHashAlgorithm = (obj: any, algIdName: keyof typeof FoundationModules.AlgId) => {
  Object.defineProperty(obj, algIdName, {
    configurable: false,
    enumerable: true,
    get: () => {
      const { AlgId } = getFoundationModules();
      return AlgId[algIdName] as number;
    },
  });
};

// eslint-disable-next-line @typescript-eslint/ban-ts-ignore
// @ts-ignore
export const HashAlgorithm: HashAlgorithmType = {};
addHashAlgorithm(HashAlgorithm, 'SHA224');
addHashAlgorithm(HashAlgorithm, 'SHA256');
addHashAlgorithm(HashAlgorithm, 'SHA384');
addHashAlgorithm(HashAlgorithm, 'SHA512');
