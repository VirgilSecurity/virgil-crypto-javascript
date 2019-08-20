import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export type Data = import('@virgilsecurity/data-utils').Data;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPrivateKey = any;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPublicKey = any;

export interface VirgilKeyPair {
  privateKey: VirgilPrivateKey;
  publicKey: VirgilPublicKey;
}
