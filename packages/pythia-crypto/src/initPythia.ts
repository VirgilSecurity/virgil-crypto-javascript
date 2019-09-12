import initPythiaModules from '@virgilsecurity/core-pythia';

import { getPythiaModules, setPythiaModules } from './pythiaModules';

export async function initPythia() {
  try {
    getPythiaModules();
    console.warn('Pythia modules are already set. Further calls to `initPythia` are ignored.');
  } catch (_) {
    return;
  }
  const pythiaModules = await initPythiaModules();
  setPythiaModules(pythiaModules);
}
