declare module '@virgilsecurity/core-foundation' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type FoundationModules = any;
  function initFoundation(): Promise<FoundationModules>;
  export default initFoundation;
}

declare module '@virgilsecurity/core-foundation/*' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type FoundationModules = any;
  function initFoundation(): Promise<FoundationModules>;
  export default initFoundation;
}
