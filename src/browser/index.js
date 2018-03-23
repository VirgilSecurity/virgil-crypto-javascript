import { wrapper } from './utils/crypto-utils';
import Virgil from './utils/crypto-module';

wrapper.wrapMethods(Virgil.VirgilTinyCipher.prototype);

export { encrypt } from './encrypt';
export { decrypt } from './decrypt';
export { sign } from './sign';
export { verify } from './verify';
export { generateKeyPair } from './generate-key-pair';
export { changePrivateKeyPassword } from './change-private-key-password';
export { obfuscate } from './obfuscate';
export { hash } from './hash';
export { publicKeyToDER } from './public-key-to-der';
export { privateKeyToDER } from './private-key-to-der';
export { extractPublicKey } from './extract-public-key';
export { encryptPrivateKey } from './encrypt-private-key';
export { decryptPrivateKey } from './decrypt-private-key';
export { signThenEncrypt } from './sign-then-encrypt';
export { decryptThenVerify } from './decrypt-then-verify';
export { default as KeyPairType } from '../lib/key-pair-type';
export const HashAlgorithm = Virgil.VirgilHashAlgorithm;
export const VirgilTinyCipher = Virgil.VirgilTinyCipher;
