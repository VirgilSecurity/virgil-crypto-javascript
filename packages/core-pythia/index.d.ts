declare module '@virgilsecurity/core-pythia' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type PythiaModules = any;
  function initRatchet(): Promise<PythiaModules>;
  export default initPythia;
}

declare module '@virgilsecurity/core-pythia/*' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type PythiaModules = any;
  function initPythia(): Promise<PythiaModules>;
  export default initPythia;
}
