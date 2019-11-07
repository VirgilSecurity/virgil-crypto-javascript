import { PheModules } from './types';

let pheModules: PheModules | undefined;

export const setPheModules = (modules: PheModules) => {
  if (pheModules) {
    // eslint-disable-next-line no-console
    console.warn('PHE modules are already set. Further calls to `setPheModules` are ignored.');
    return;
  }
  pheModules = modules;
};

export const getPheModules = () => {
  if (!pheModules) {
    throw new Error('You need to call `setPheModules` first');
  }
  return pheModules;
};

export const hasPheModules = () => typeof pheModules !== 'undefined';
