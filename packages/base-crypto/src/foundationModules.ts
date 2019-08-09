import { FoundationModules } from '@virgilsecurity/core-foundation';

let foundationModules: FoundationModules | undefined;

export const setFoundationModules = (modules: FoundationModules) => {
  foundationModules = modules;
};

export const getFoundationModules = () => {
  if (!foundationModules) {
    throw new Error('You need to call `setFoundationModules` first');
  }
  return foundationModules;
};
