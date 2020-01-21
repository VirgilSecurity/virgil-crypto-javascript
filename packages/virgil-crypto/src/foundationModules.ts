import initFoundationModules from '@virgilsecurity/core-foundation';
import { ModuleInitializer } from '@virgilsecurity/init-utils';

import { createGlobalInstances, resetGlobalInstances } from './globalInstances';
import { FoundationModules } from './types';

export const moduleInitializer = new ModuleInitializer();
const FOUNDATION_MODULE_KEY = 'foundation';

moduleInitializer.addModule<FoundationModules>(FOUNDATION_MODULE_KEY, initFoundationModules);

moduleInitializer.on('load', (name, modules) => {
  if (name === FOUNDATION_MODULE_KEY) {
    resetGlobalInstances();
    createGlobalInstances(modules);
  }
});

moduleInitializer.on('remove', name => {
  if (name === FOUNDATION_MODULE_KEY) {
    resetGlobalInstances();
  }
});

export const hasFoundationModules = () => moduleInitializer.hasModule(FOUNDATION_MODULE_KEY);

export const getFoundationModules = () =>
  moduleInitializer.getModule<FoundationModules>(FOUNDATION_MODULE_KEY);

export const setFoundationModules = (foundationModules: FoundationModules) => {
  moduleInitializer.setModule<FoundationModules>(FOUNDATION_MODULE_KEY, foundationModules);
};

export const initCrypto = moduleInitializer.loadModules;
