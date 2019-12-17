import initFoundationModules from '@virgilsecurity/core-foundation';
import { ModuleInitializer } from '@virgilsecurity/init-utils';

import { FoundationModules } from './types';

export const moduleInitializer = new ModuleInitializer();
moduleInitializer.addModule<FoundationModules>('foundation', initFoundationModules);

export const hasFoundationModules = () => moduleInitializer.hasModule('foundation');
export const getFoundationModules = () =>
  moduleInitializer.getModule<FoundationModules>('foundation');
export const setFoundationModules = (foundationModules: FoundationModules) => {
  moduleInitializer.setModule<FoundationModules>('foundation', foundationModules);
};
export const initCrypto = moduleInitializer.loadModules;
