import initPythiaModules from '@virgilsecurity/core-pythia';

import { getPythiaModules, setPythiaModules } from './pythiaModules';

export async function initPythia() {
  try {
    getPythiaModules();
    // eslint-disable-next-line no-console
    console.warn('Pythia modules are already set. Further calls to `initPythia` are ignored.');
    return;
    // eslint-disable-next-line no-empty
  } catch (_) {}
  const pythiaModules = await initPythiaModules();
  setPythiaModules(pythiaModules);
}
