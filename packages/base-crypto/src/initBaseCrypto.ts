import { FoundationModules } from '@virgilsecurity/core-foundation';

import { initHashAlgorithm, HashAlgorithmType } from './initHashAlgorithm';
import { initKeyPairType, KeyPairTypeType } from './initKeyPairType';
import { initVirgilCrypto, VirgilCryptoReturnType } from './initVirgilCrypto';
import { initVirgilStreamCipher, VirgilStreamCipherReturnType } from './initVirgilStreamCipher';
import {
  initVirgilStreamDecipher,
  VirgilStreamDecipherReturnType,
} from './initVirgilStreamDecipher';
import { initVirgilStreamSigner, VirgilStreamSignerReturnType } from './initVirgilStreamSigner';
import {
  initVirgilStreamVerifier,
  VirgilStreamVerifierReturnType,
} from './initVirgilStreamVerifier';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export interface CryptoModules {
  HashAlgorithm: HashAlgorithmType;
  KeyPairType: KeyPairTypeType;
  VirgilCrypto: VirgilCryptoReturnType;
  VirgilStreamCipher: VirgilStreamCipherReturnType;
  VirgilStreamDecipher: VirgilStreamDecipherReturnType;
  VirgilStreamSigner: VirgilStreamSignerReturnType;
  VirgilStreamVerifier: VirgilStreamVerifierReturnType;
  VirgilPrivateKey: typeof VirgilPrivateKey;
  VirgilPublicKey: typeof VirgilPublicKey;
}

export const initBaseCrypto = (foundationModules: FoundationModules): CryptoModules => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const modules: any = {};
  modules.HashAlgorithm = initHashAlgorithm(foundationModules);
  modules.KeyPairType = initKeyPairType(foundationModules);
  modules.VirgilCrypto = initVirgilCrypto(foundationModules, modules);
  modules.VirgilStreamCipher = initVirgilStreamCipher(foundationModules);
  modules.VirgilStreamDecipher = initVirgilStreamDecipher(foundationModules);
  modules.VirgilStreamSigner = initVirgilStreamSigner(foundationModules);
  modules.VirgilStreamVerifier = initVirgilStreamVerifier(foundationModules);
  modules.VirgilPrivateKey = VirgilPrivateKey;
  modules.VirgilPublicKey = VirgilPublicKey;
  return modules;
};
