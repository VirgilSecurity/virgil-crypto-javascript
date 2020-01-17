import initFoundationModules from '@virgilsecurity/core-foundation';
import { ModuleInitializer } from '@virgilsecurity/init-utils';

import { createGlobalInstances, resetGlobalInstances } from './globalInstances';
import { FoundationModules } from './types';

export const moduleInitializer = new ModuleInitializer();

moduleInitializer.addModule<FoundationModules>('foundation', initFoundationModules);

moduleInitializer.on('load', (name, modules) => {
  if (name === 'foundation') {
    resetGlobalInstances();
    createGlobalInstances(modules);
  }
});

moduleInitializer.on('remove', name => {
  if (name === 'foundation') {
    resetGlobalInstances();
  }
});

export const hasFoundationModules = () => moduleInitializer.hasModule('foundation');

export const getFoundationModules = () =>
  moduleInitializer.getModule<FoundationModules>('foundation');

export const setFoundationModules = (foundationModules: FoundationModules) => {
  moduleInitializer.setModule<FoundationModules>('foundation', foundationModules);
};

export const initCrypto = moduleInitializer.loadModules;
