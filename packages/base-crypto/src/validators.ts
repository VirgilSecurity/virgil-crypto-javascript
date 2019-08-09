import { hasLowLevelPrivateKey } from './privateKeyUtils';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export function validatePrivateKey(privateKey: VirgilPrivateKey, label: string = 'privateKey') {
  if (
    privateKey == null ||
    !(privateKey.identifier instanceof Uint8Array) ||
    !hasLowLevelPrivateKey(privateKey)
  ) {
    throw new TypeError(`\`${label}\` is not a VirgilPrivateKey.`);
  }
}

export function validatePublicKey(publicKey: VirgilPublicKey, label: string = 'publicKey') {
  if (
    publicKey == null ||
    !(publicKey.identifier instanceof Uint8Array) ||
    typeof publicKey.key !== 'object'
  ) {
    throw new TypeError(`\`${label}\` is not a VirgilPublicKey.`);
  }
}

export function validatePublicKeysArray(
  publicKeys: VirgilPublicKey[],
  label: string = 'publicKeys',
) {
  if (publicKeys.length === 0) {
    throw new TypeError(`\`${label}\` array must not be empty.`);
  }
  publicKeys.forEach(publicKey => validatePublicKey(publicKey));
}
