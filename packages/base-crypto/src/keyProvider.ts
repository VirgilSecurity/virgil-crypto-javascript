import { getFoundationModules } from './foundationModules';
import { KeyProvider } from './types';

let keyProvider: KeyProvider | undefined;

export const getKeyProvider = () => {
  if (keyProvider) {
    return keyProvider;
  }
  const foundationModules = getFoundationModules();
  keyProvider = new foundationModules.KeyProvider() as KeyProvider;
  try {
    keyProvider.setupDefaults();
  } catch (error) {
    keyProvider.delete();
    keyProvider = undefined;
    throw error;
  }
  return keyProvider;
};

export const importPrivateKey = (serializedPrivateKey: Uint8Array) =>
  getKeyProvider().importPrivateKey(serializedPrivateKey);

export const importPublicKey = (serializedPublicKey: Uint8Array) =>
  getKeyProvider().importPublicKey(serializedPublicKey);