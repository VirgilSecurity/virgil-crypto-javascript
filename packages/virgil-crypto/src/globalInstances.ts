import { FoundationModules } from './types';

let random: FoundationModules.CtrDrbg | undefined;
let keyProvider: FoundationModules.KeyProvider | undefined;

const ensureExist = () => {
  if (!random || !keyProvider) {
    throw new Error(
      "Cannot use global instances if the 'resetGlobalInstances' function has been called or 'createGlobalInstances' function has not been called yet.",
    );
  }
};

export const getRandom = () => {
  ensureExist();
  return random!;
};

export const getKeyProvider = () => {
  ensureExist();
  return keyProvider!;
};

export const createGlobalInstances = (foundationModules: FoundationModules) => {
  random = new foundationModules.CtrDrbg();
  try {
    random.setupDefaults();
  } catch (error) {
    random.delete();
    throw error;
  }
  keyProvider = new foundationModules.KeyProvider();
  keyProvider.random = random;
  try {
    keyProvider.setupDefaults();
  } catch (error) {
    random.delete();
    keyProvider.delete();
    throw error;
  }
};

export const resetGlobalInstances = () => {
  if (!random && !keyProvider) {
    return;
  }
  ensureExist();
  random!.delete();
  keyProvider!.delete();
  random = undefined;
  keyProvider = undefined;
};
