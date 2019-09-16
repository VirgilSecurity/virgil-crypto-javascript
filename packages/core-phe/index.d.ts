declare module '@virgilsecurity/core-phe' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type PheModules = any;
  function initPhe(): Promise<PheModules>;
  export default initPhe;
}

declare module '@virgilsecurity/core-phe/*' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type PheModules = any;
  function initPhe(): Promise<PheModules>;
  export default initPhe;
}
