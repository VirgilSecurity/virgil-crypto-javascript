import initFoundationModules from '@virgilsecurity/core-foundation';
import { ModuleInitializer } from '@virgilsecurity/initializer';

import { FoundationModules } from './types';

export const foundationInitializer = new ModuleInitializer<FoundationModules>(
  initFoundationModules,
);

export const hasFoundationModules = () => foundationInitializer.isInitialized;
export const getFoundationModules = () => foundationInitializer.module;
export const setFoundationModules = (foundationModules: FoundationModules) => {
  foundationInitializer.module = foundationModules;
};
export const initCrypto = foundationInitializer.initialize;
