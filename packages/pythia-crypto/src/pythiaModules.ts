import initPythiaModules from '@virgilsecurity/core-pythia';
import { ModuleInitializer } from '@virgilsecurity/init-utils';

import { PythiaModules } from './types';

export const pythiaInitializer = new ModuleInitializer<PythiaModules>(async () => {
  const pythiaModules = await initPythiaModules();
  try {
    pythiaModules.Pythia.configure();
  } catch (error) {
    pythiaModules.Pythia.cleanup();
    throw error;
  }
  return pythiaModules;
});

export const hasPythiaModules = () => pythiaInitializer.isInitialized;
export const getPythiaModules = () => pythiaInitializer.module;
export const setPythiaModules = (pythiaModules: PythiaModules) => {
  pythiaInitializer.module = pythiaModules;
};
export const initPythia = pythiaInitializer.initialize;
