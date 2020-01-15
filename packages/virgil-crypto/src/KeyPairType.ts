import { moduleInitializer } from './foundationModules';
import { FoundationModules } from './types';

export enum KeyPairType {
  DEFAULT = 'DEFAULT',
  ED25519 = 'ED25519',
  CURVE25519 = 'CURVE25519',
  SECP256R1 = 'SECP256R1',
  RSA_2048 = 'RSA_2048',
  RSA_3072 = 'RSA_3072',
  RSA_4096 = 'RSA_4096',
  RSA_8192 = 'RSA_8192',
  CURVE25519_ROUND5_ED25519_FALCON = 'CURVE25519_ROUND5_ED25519_FALCON',
  CURVE25519_ED25519 = 'CURVE25519_ED25519',
}

export interface KeyPairTypeConfig {
  type: KeyPairType;
  algId?: FoundationModules.AlgId;
  bitlen?: number;
  cipherAlgIds?: FoundationModules.AlgId[];
  signerAlgIds?: FoundationModules.AlgId[];
}

export const getKeyPairTypeConfig = (
  keyPairType: KeyPairType[keyof KeyPairType],
): KeyPairTypeConfig => {
  const { AlgId } = moduleInitializer.getModule<FoundationModules>('foundation');
  switch (keyPairType) {
    case KeyPairType.DEFAULT:
      return {
        type: KeyPairType.DEFAULT,
        algId: AlgId.ED25519,
      };
    case KeyPairType.ED25519:
      return {
        type: KeyPairType.ED25519,
        algId: AlgId.ED25519,
      };
    case KeyPairType.CURVE25519:
      return {
        type: KeyPairType.CURVE25519,
        algId: AlgId.CURVE25519,
      };
    case KeyPairType.SECP256R1:
      return {
        type: KeyPairType.SECP256R1,
        algId: AlgId.SECP256R1,
      };
    case KeyPairType.RSA_2048:
      return {
        type: KeyPairType.RSA_2048,
        algId: AlgId.RSA,
        bitlen: 2048,
      };
    case KeyPairType.RSA_3072:
      return {
        type: KeyPairType.RSA_3072,
        algId: AlgId.RSA,
        bitlen: 3072,
      };
    case KeyPairType.RSA_4096:
      return {
        type: KeyPairType.RSA_4096,
        algId: AlgId.RSA,
        bitlen: 4096,
      };
    case KeyPairType.RSA_8192:
      return {
        type: KeyPairType.RSA_8192,
        algId: AlgId.RSA,
        bitlen: 8192,
      };
    case KeyPairType.CURVE25519_ROUND5_ED25519_FALCON:
      return {
        type: KeyPairType.CURVE25519_ROUND5_ED25519_FALCON,
        cipherAlgIds: [AlgId.CURVE25519, AlgId.ROUND5_ND_5KEM_5D],
        signerAlgIds: [AlgId.ED25519, AlgId.FALCON],
      };
    case KeyPairType.CURVE25519_ED25519:
      return {
        type: KeyPairType.CURVE25519_ED25519,
        cipherAlgIds: [AlgId.CURVE25519, AlgId.NONE],
        signerAlgIds: [AlgId.ED25519, AlgId.NONE],
      };
    default:
      throw new TypeError(`Unknown key pair type '${keyPairType}'.`);
  }
};

export const isRSAKeyPairType = (keyPairType: KeyPairType[keyof KeyPairType]) =>
  keyPairType === KeyPairType.RSA_2048 ||
  keyPairType === KeyPairType.RSA_3072 ||
  keyPairType === KeyPairType.RSA_4096 ||
  keyPairType === KeyPairType.RSA_8192;

export const isCompoundKeyPairType = (keyPairType: KeyPairType[keyof KeyPairType]) =>
  keyPairType === KeyPairType.CURVE25519_ROUND5_ED25519_FALCON ||
  keyPairType === KeyPairType.CURVE25519_ED25519;
