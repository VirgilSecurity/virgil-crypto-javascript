import { getFoundationModules } from './foundationModules';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const addKeyPairType = (obj: any, name: string, algIdName: string, bitlen?: number) => {
  Object.defineProperty(obj, name, {
    configurable: false,
    enumerable: true,
    get: () => {
      const { AlgId } = getFoundationModules();
      return {
        bitlen,
        algId: AlgId[algIdName] as number,
      };
    },
  });
};

export interface KeyPairTypeObject {
  algId: number;
  bitlen?: number;
}

export interface KeyPairTypeType {
  Default: KeyPairTypeObject;
  ED25519: KeyPairTypeObject;
  CURVE25519: KeyPairTypeObject;
  SECP256R1: KeyPairTypeObject;
  RSA_2048: KeyPairTypeObject;
  RSA_3072: KeyPairTypeObject;
  RSA_4096: KeyPairTypeObject;
  RSA_8192: KeyPairTypeObject;
}

// @ts-ignore
export const KeyPairType: KeyPairTypeType = {};
addKeyPairType(KeyPairType, 'Default', 'ED25519');
addKeyPairType(KeyPairType, 'ED25519', 'ED25519');
addKeyPairType(KeyPairType, 'CURVE25519', 'CURVE25519');
addKeyPairType(KeyPairType, 'SECP256R1', 'SECP256R1');
addKeyPairType(KeyPairType, 'RSA_2048', 'RSA', 2048);
addKeyPairType(KeyPairType, 'RSA_3072', 'RSA', 3072);
addKeyPairType(KeyPairType, 'RSA_4096', 'RSA', 4096);
addKeyPairType(KeyPairType, 'RSA_8192', 'RSA', 8192);
