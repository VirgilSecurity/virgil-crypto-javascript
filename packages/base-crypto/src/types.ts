import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export type NodeBuffer = import('@virgilsecurity/crypto-types').NodeBuffer;
export type Data = import('@virgilsecurity/crypto-types').Data;
export type IPrivateKey = import('@virgilsecurity/crypto-types').IPrivateKey;
export type IPublicKey = import('@virgilsecurity/crypto-types').IPublicKey;
export type IKeyPair = import('@virgilsecurity/crypto-types').IKeyPair;
export type ICrypto = import('@virgilsecurity/crypto-types').ICrypto;

export interface VirgilKeyPair extends IKeyPair {
  privateKey: VirgilPrivateKey;
  publicKey: VirgilPublicKey;
}
