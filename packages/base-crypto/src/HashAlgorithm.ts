import { getFoundationModules } from './foundationModules';

export interface HashAlgorithmType {
  SHA224: number;
  SHA256: number;
  SHA384: number;
  SHA512: number;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const addHashAlgorithm = (obj: any, algIdName: string) => {
  Object.defineProperty(obj, algIdName, {
    configurable: false,
    enumerable: true,
    get: () => {
      const { AlgId } = getFoundationModules();
      return AlgId[algIdName] as number;
    },
  });
};

// @ts-ignore
export const HashAlgorithm: HashAlgorithmType = {};
addHashAlgorithm(HashAlgorithm, 'SHA224');
addHashAlgorithm(HashAlgorithm, 'SHA256');
addHashAlgorithm(HashAlgorithm, 'SHA384');
addHashAlgorithm(HashAlgorithm, 'SHA512');
