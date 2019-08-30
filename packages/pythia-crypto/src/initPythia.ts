import initPythiaModules from "@virgilsecurity/core-pythia";

import { setPythiaModules } from "./pythiaModules";

export async function initPythia() {
  const pythiaModules = await initPythiaModules();
  setPythiaModules(pythiaModules);
}
