import initPythiaModules from '@virgilsecurity/core-pythia';
import { ModuleInitializer } from '@virgilsecurity/init-utils';

import { PythiaModules } from './types';

export const moduleInitializer = new ModuleInitializer();

moduleInitializer.addModule<PythiaModules>('pythia', initPythiaModules);

moduleInitializer.on('load', (name, modules) => {
  if (name === 'pythia') {
    try {
      modules.Pythia.configure();
    } catch (error) {
      modules.Pythia.cleanup();
      throw error;
    }
  }
});

moduleInitializer.on('remove', (name, modules) => {
  if (name === 'pythia') {
    modules.Pythia.cleanup();
  }
});

export const hasPythiaModules = () => moduleInitializer.hasModule('pythia');

export const getPythiaModules = () => moduleInitializer.getModule<PythiaModules>('pythia');

export const setPythiaModules = (pythiaModules: PythiaModules) => {
  moduleInitializer.setModule<PythiaModules>('pythia', pythiaModules);
};

export const initPythia = moduleInitializer.loadModules;
