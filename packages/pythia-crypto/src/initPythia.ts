import initPythiaModules from '@virgilsecurity/core-pythia';

import { getPythiaModules, setPythiaModules } from './pythiaModules';

export async function initPythia() {
  try {
    getPythiaModules();
    console.warn('Pythia modules are already set. Further calls to `initPythia` are ignored.');
    return;
  } catch (_) {}
  const pythiaModules = await initPythiaModules();
  setPythiaModules(pythiaModules);
}
