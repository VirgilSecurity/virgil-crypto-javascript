import initPheModules from '@virgilsecurity/core-phe';

import { hasPheModules, setPheModules } from './pheModules';

export async function initPhe() {
  if (hasPheModules()) {
    // eslint-disable-next-line no-console
    console.warn('PHE modules are already set. Further calls to `initPhe` are ignored.');
    return;
  }
  const pheModules = await initPheModules();
  setPheModules(pheModules);
}
