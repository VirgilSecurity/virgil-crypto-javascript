declare module '@virgilsecurity/core-foundation' {
  export type FoundationModules = any;
  function initRatchet(): Promise<FoundationModules>;
  export default initRatchet;
}

declare module '@virgilsecurity/core-foundation/*' {
  export type FoundationModules = any;
  function initRatchet(): Promise<FoundationModules>;
  export default initRatchet;
}
