import initPythiaModules from '@virgilsecurity/core-pythia';

import { hasPythiaModules, setPythiaModules } from './pythiaModules';

export async function initPythia() {
  if (hasPythiaModules()) {
    // eslint-disable-next-line no-console
    console.warn('Pythia modules are already set. Further calls to `initPythia` are ignored.');
    return;
  }
  const pythiaModules = await initPythiaModules();
  setPythiaModules(pythiaModules);
}
