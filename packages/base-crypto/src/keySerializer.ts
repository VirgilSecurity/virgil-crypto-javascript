import { getFoundationModules } from './foundationModules';

let keySerializer: FoundationModules.KeyAsn1Serializer | undefined;

export const getKeySerializer = () => {
  if (keySerializer) {
    return keySerializer;
  }
  const foundationModules = getFoundationModules();
  keySerializer = new foundationModules.KeyAsn1Serializer();
  try {
    keySerializer.setupDefaults();
  } catch (error) {
    keySerializer.delete();
    keySerializer = undefined;
    throw error;
  }
  return keySerializer;
};

export const serializePrivateKey = (lowLevelPrivateKey: FoundationModules.PrivateKey) =>
  getKeySerializer().serializePrivateKey(lowLevelPrivateKey);

export const serializePublicKey = (lowLevelPublicKey: FoundationModules.PublicKey) =>
  getKeySerializer().serializePublicKey(lowLevelPublicKey);
