declare module '@virgilsecurity/core-phe' {
  export type PheModules = any;
  function initRatchet(): Promise<PheModules>;
  export default initRatchet;
}

declare module '@virgilsecurity/core-phe/*' {
  export type PheModules = any;
  function initRatchet(): Promise<PheModules>;
  export default initRatchet;
}
