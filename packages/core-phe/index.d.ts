declare module '@virgilsecurity/core-phe' {
  export type PheModules = any;
  function initPhe(): Promise<PheModules>;
  export default initPhe;
}

declare module '@virgilsecurity/core-phe/*' {
  export type PheModules = any;
  function initPhe(): Promise<PheModules>;
  export default initPhe;
}
