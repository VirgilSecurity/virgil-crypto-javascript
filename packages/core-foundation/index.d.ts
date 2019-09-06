declare module '@virgilsecurity/core-foundation' {
  export type FoundationModules = any;
  function initFoundation(): Promise<FoundationModules>;
  export default initFoundation;
}

declare module '@virgilsecurity/core-foundation/*' {
  export type FoundationModules = any;
  function initFoundation(): Promise<FoundationModules>;
  export default initFoundation;
}
