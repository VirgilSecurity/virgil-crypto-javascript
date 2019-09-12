import { getFoundationModules, setFoundationModules } from '@virgilsecurity/base-crypto';
// @ts-ignore
import initFoundation from '@virgilsecurity/core-foundation';

export * from '@virgilsecurity/base-crypto';
export * from '@virgilsecurity/sdk-crypto';

export const initCrypto = async () => {
  try {
    getFoundationModules();
    console.warn('Foundation modules are already set. Further calls to `initCrypto` are ignored.');
  } catch (_) {
    return;
  }
  const foundationModules = await initFoundation();
  setFoundationModules(foundationModules);
};
