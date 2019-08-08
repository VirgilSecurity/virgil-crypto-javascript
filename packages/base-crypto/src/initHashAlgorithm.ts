import { FoundationModules } from '@virgilsecurity/core-foundation';

export const initHashAlgorithm = (foundationModules: FoundationModules) => {
  const { AlgId } = foundationModules;
  return Object.freeze({
    SHA224: AlgId.SHA224 as number,
    SHA256: AlgId.SHA256 as number,
    SHA384: AlgId.SHA384 as number,
    SHA512: AlgId.SHA512 as number,
  });
};

export type HashAlgorithmType = ReturnType<typeof initHashAlgorithm>;
