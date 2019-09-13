import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export type NodeBuffer = import('@virgilsecurity/crypto-types').NodeBuffer;
export type Data = import('@virgilsecurity/crypto-types').Data;
export type IPrivateKey = import('@virgilsecurity/crypto-types').IPrivateKey;
export type IPublicKey = import('@virgilsecurity/crypto-types').IPublicKey;
export type IKeyPair = import('@virgilsecurity/crypto-types').IKeyPair;
export type ICrypto = import('@virgilsecurity/crypto-types').ICrypto;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPrivateKey = any;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type LowLevelPublicKey = any;

export interface KeyAsn1Serializer {
  serializePrivateKey(lowLevelPrivateKey: LowLevelPrivateKey): Uint8Array;
  serializePublicKey(lowLevelPublicKey: LowLevelPublicKey): Uint8Array;
  setupDefaults(): void;
  delete(): void;
}

export interface KeyProvider {
  importPrivateKey(serializedPrivateKey: Uint8Array): LowLevelPrivateKey;
  importPublicKey(serializedPublicKey: Uint8Array): LowLevelPublicKey;
  setupDefaults(): void;
  delete(): void;
}

export interface VirgilKeyPair extends IKeyPair {
  privateKey: VirgilPrivateKey;
  publicKey: VirgilPublicKey;
}
