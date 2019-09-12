import { FoundationModules } from '@virgilsecurity/core-foundation';

let foundationModules: FoundationModules | undefined;

export const setFoundationModules = (modules: FoundationModules) => {
  if (foundationModules) {
    // eslint-disable-next-line no-console
    console.warn(
      'Foundation modules are already set. Further calls to `setFoundationModules` are ignored.',
    );
    return;
  }
  foundationModules = modules;
};

export const getFoundationModules = () => {
  if (!foundationModules) {
    throw new Error('You need to call `setFoundationModules` first');
  }
  return foundationModules;
};
