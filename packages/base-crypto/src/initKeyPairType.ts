import { FoundationModules } from '@virgilsecurity/core-foundation';

export interface KeyPairTypeObject {
  algId: number;
  bitlen?: number;
}

const createKeyPairType = (algId: number, bitlen?: number) =>
  Object.freeze({
    algId,
    bitlen,
  }) as KeyPairTypeObject;

export const initKeyPairType = (foundationModules: FoundationModules) => {
  const { AlgId } = foundationModules;
  const ED25519 = createKeyPairType(AlgId.ED25519);
  const CURVE25519 = createKeyPairType(AlgId.CURVE25519);
  const SECP256R1 = createKeyPairType(AlgId.SECP256R1);
  const RSA_2048 = createKeyPairType(AlgId.RSA, 2048);
  const RSA_3072 = createKeyPairType(AlgId.RSA, 3072);
  const RSA_4096 = createKeyPairType(AlgId.RSA, 4096);
  const RSA_8192 = createKeyPairType(AlgId.RSA, 8192);
  const Default = ED25519;
  return Object.freeze({
    Default,
    ED25519,
    CURVE25519,
    SECP256R1,
    RSA_2048,
    RSA_3072,
    RSA_4096,
    RSA_8192,
  });
};

export type KeyPairTypeType = ReturnType<typeof initKeyPairType>;
