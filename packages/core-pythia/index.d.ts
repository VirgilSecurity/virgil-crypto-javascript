declare module '@virgilsecurity/core-pythia' {
  export type PythiaModules = any;
  function initRatchet(): Promise<PythiaModules>;
  export default initPythia;
}

declare module '@virgilsecurity/core-pythia/*' {
  export type PythiaModules = any;
  function initPythia(): Promise<PythiaModules>;
  export default initPythia;
}
