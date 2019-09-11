import { setFoundationModules } from '@virgilsecurity/base-crypto';
// @ts-ignore
import initFoundation from '@virgilsecurity/core-foundation';

export * from '@virgilsecurity/base-crypto';
export * from '@virgilsecurity/sdk-crypto';

export const initCrypto = async () => {
  const foundationModules = await initFoundation();
  setFoundationModules(foundationModules);
};
