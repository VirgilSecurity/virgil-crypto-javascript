import initPythiaModules from '@virgilsecurity/core-pythia';
import { ModuleInitializer } from '@virgilsecurity/init-utils';

import { PythiaModules } from './types';

export const moduleInitializer = new ModuleInitializer();
moduleInitializer.addModule<PythiaModules>('pythia', async () => {
  const pythiaModules = await initPythiaModules();
  try {
    pythiaModules.Pythia.configure();
  } catch (error) {
    pythiaModules.Pythia.cleanup();
    throw error;
  }
  return pythiaModules;
});

export const hasPythiaModules = () => moduleInitializer.hasModule('pythia');
export const getPythiaModules = () => moduleInitializer.getModule<PythiaModules>('pythia');
export const setPythiaModules = (pythiaModules: PythiaModules) => {
  moduleInitializer.setModule<PythiaModules>('pythia', pythiaModules);
};
export const initPythia = moduleInitializer.loadModules;
