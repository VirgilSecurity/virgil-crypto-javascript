import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export type IPrivateKey = import('@virgilsecurity/crypto-types').IPrivateKey;
export type IPublicKey = import('@virgilsecurity/crypto-types').IPublicKey;
export type IKeyPair = import('@virgilsecurity/crypto-types').IKeyPair;
export type ICrypto = import('@virgilsecurity/crypto-types').ICrypto;

export type Data = import('@virgilsecurity/data-utils').Data;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPrivateKey = any;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPublicKey = any;

export interface VirgilKeyPair extends IKeyPair {
  privateKey: VirgilPrivateKey;
  publicKey: VirgilPublicKey;
}
