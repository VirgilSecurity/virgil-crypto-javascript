import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export enum StringEncoding {
  utf8 = 'utf8',
  base64 = 'base64',
  hex = 'hex',
}

export interface StringWithEncoding {
  value: string;
  encoding: keyof typeof StringEncoding;
}

export type Data = Uint8Array | StringWithEncoding | string;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPrivateKey = any;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPublicKey = any;

export interface VirgilKeyPair {
  privateKey: VirgilPrivateKey;
  publicKey: VirgilPublicKey;
}
