declare module '@virgilsecurity/core-ratchet' {
  export type RatchetModules = any;
  function initRatchet(): Promise<RatchetModules>;
  export default initRatchet;
}

declare module '@virgilsecurity/core-ratchet/*' {
  export type RatchetModules = any;
  function initRatchet(): Promise<RatchetModules>;
  export default initRatchet;
}
