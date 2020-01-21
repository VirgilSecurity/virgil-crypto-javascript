import { NodeBuffer } from '@virgilsecurity/data-utils';

import { MIN_GROUP_ID_BYTE_LENGTH } from './constants';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export function validatePrivateKey(privateKey: any) {
  if (!(privateKey instanceof VirgilPrivateKey)) {
    throw new TypeError("An argument is not an instance of 'VirgilPrivateKey' class.");
  }
  if (privateKey.isDisposed) {
    throw new TypeError(
      "Cannot use an instance of 'VirgilPrivateKey' class after it was disposed.",
    );
  }
}

export function validatePublicKey(publicKey: any) {
  if (!(publicKey instanceof VirgilPublicKey)) {
    throw new TypeError("An argument is not a 'VirgilPublicKey'.");
  }
  if (publicKey.isDisposed) {
    throw new TypeError("Cannot use an instance of 'VirgilPublicKey' class after it was disposed.");
  }
}

export function validatePublicKeysArray(publicKeys: any) {
  if (!Array.isArray(publicKeys)) {
    throw new TypeError('An argument is not an array.');
  }
  if (!publicKeys.length) {
    throw new TypeError("An array of 'VirgilPublicKey' instances should not be empty.");
  }
  publicKeys.forEach(validatePublicKey);
}

export function validatePositiveNonZeroNumber(number: any) {
  if (typeof number !== 'number') {
    throw new TypeError('An argument is not a number.');
  }
  if (number <= 0) {
    throw new TypeError(`An argument should be greater that '0', but received '${number}'.`);
  }
}

export function validateGroupId(groupId: any) {
  if (!(groupId instanceof Uint8Array)) {
    throw new TypeError("An argument is not an instance of 'Uint8Array' class.");
  }
  if (groupId.byteLength < MIN_GROUP_ID_BYTE_LENGTH) {
    throw new TypeError(
      `An argument byte length is too small. Expected to be at least '${MIN_GROUP_ID_BYTE_LENGTH}' bytes.`,
    );
  }
}
