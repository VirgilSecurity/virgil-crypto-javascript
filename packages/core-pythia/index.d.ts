declare module '@virgilsecurity/core-pythia' {
  export type PythiaModules = any;
  function initRatchet(): Promise<PythiaModules>;
  export default initRatchet;
}

declare module '@virgilsecurity/core-pythia/*' {
  export type PythiaModules = any;
  function initRatchet(): Promise<PythiaModules>;
  export default initRatchet;
}
