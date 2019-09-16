declare module '@virgilsecurity/core-ratchet' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type RatchetModules = any;
  function initRatchet(): Promise<RatchetModules>;
  export default initRatchet;
}

declare module '@virgilsecurity/core-ratchet/*' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type RatchetModules = any;
  function initRatchet(): Promise<RatchetModules>;
  export default initRatchet;
}
