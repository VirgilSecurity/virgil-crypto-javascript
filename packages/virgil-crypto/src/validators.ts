import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export function validatePrivateKey(privateKey: VirgilPrivateKey, label = 'privateKey') {
  if (
    privateKey == null ||
    !(privateKey.identifier instanceof Uint8Array) ||
    !(typeof privateKey.lowLevelPrivateKey === 'object') ||
    !(typeof privateKey.isDisposed === 'boolean')
  ) {
    throw new TypeError(`\`${label}\` is not a VirgilPrivateKey.`);
  }
  if (privateKey.isDisposed) {
    throw new Error(`Cannot use \`${label}\` after it was disposed.`);
  }
}

export function validatePublicKey(publicKey: VirgilPublicKey, label = 'publicKey') {
  if (
    publicKey == null ||
    !(publicKey.identifier instanceof Uint8Array) ||
    !(typeof publicKey.lowLevelPublicKey === 'object') ||
    !(typeof publicKey.isDisposed === 'boolean')
  ) {
    throw new TypeError(`\`${label}\` is not a VirgilPublicKey.`);
  }
  if (publicKey.isDisposed) {
    throw new Error(`Cannot use \`${label}\` after is was disposed.`);
  }
}

export function validatePublicKeysArray(publicKeys: VirgilPublicKey[], label = 'publicKeys') {
  if (publicKeys.length === 0) {
    throw new TypeError(`\`${label}\` array must not be empty.`);
  }
  publicKeys.forEach(publicKey => validatePublicKey(publicKey));
}
