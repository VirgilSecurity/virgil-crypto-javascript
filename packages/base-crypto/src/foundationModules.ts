// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="foundation-modules.d.ts" />

let foundationModules: typeof FoundationModules | undefined;

export const setFoundationModules = (modules: typeof FoundationModules) => {
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

export const hasFoundationModules = () => typeof foundationModules !== 'undefined';
