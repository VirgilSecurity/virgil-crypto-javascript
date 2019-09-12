import { PythiaModules } from './types';

let pythiaModules: PythiaModules | undefined;

export const setPythiaModules = (modules: PythiaModules) => {
  if (pythiaModules) {
    console.warn('Pythia modules are already set. Further calls to `setPythiaModules` are ignored.');
    return;
  }
  pythiaModules = modules;
  const { Pythia } = pythiaModules;
  Pythia.configure();
};

export const getPythiaModules = () => {
  if (!pythiaModules) {
    throw new Error('You need to call `setPythiaModules` first');
  }
  return pythiaModules;
};
