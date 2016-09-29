import { wrapper } from './utils/crypto-utils';
import Virgil from './utils/crypto-module';

wrapper.wrapPrototype(Virgil, 'VirgilTinyCipher');

export { encrypt } from './encrypt';
export { encryptAsync } from './encrypt-async';
export { decrypt } from './decrypt';
export { decryptAsync } from './decrypt-async';
export { sign } from './sign';
export { signAsync } from './sign-async';
export { verify } from './verify';
export { verifyAsync } from './verify-async';
export { generateKeyPair } from './generate-key-pair';
export { generateKeyPairAsync } from './generate-key-pair-async';
export { generateValidationToken } from './generate-validation-token';
export { changePrivateKeyPassword } from './change-private-key-password';
export { obfuscate } from './obfuscate';
export { hash } from './hash';
export { publicKeyToDER } from './public-key-to-der';
export { privateKeyToDER } from './private-key-to-der';
export { extractPublicKey } from './extract-public-key';
export { default as KeysType } from '../lib/keys-types-enum';
export { default as IdentityType } from '../lib/identity-types';
export * as util from '../lib/utils';
export const HashAlgorithm = Virgil.VirgilHashAlgorithm;
export const VirgilTinyCipher = Virgil.VirgilTinyCipher;
