import { getFoundationModules } from './foundationModules';
import { FoundationModules } from './types';

let random: FoundationModules.CtrDrbg | undefined;

export const getRandom = () => {
  if (random) {
    return random;
  }
  const foundationModules = getFoundationModules();
  random = new foundationModules.CtrDrbg();
  try {
    random.setupDefaults();
  } catch (error) {
    random.delete();
    throw error;
  }
  return random;
};
