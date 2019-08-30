import { PythiaModules } from './types';

let pythiaModules: PythiaModules | undefined;

export const setPythiaModules = (modules: PythiaModules) => {
  if (pythiaModules) {
    const { Pythia } = pythiaModules;
    Pythia.cleanup();
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
