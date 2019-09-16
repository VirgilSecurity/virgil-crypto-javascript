import { hasFoundationModules, setFoundationModules } from '@virgilsecurity/base-crypto';
// eslint-disable-next-line @typescript-eslint/ban-ts-ignore
// @ts-ignore
import initFoundation from '@virgilsecurity/core-foundation';

export * from '@virgilsecurity/base-crypto';
export * from '@virgilsecurity/sdk-crypto';

export const initCrypto = async () => {
  if (hasFoundationModules()) {
    // eslint-disable-next-line no-console
    console.warn('Foundation modules are already set. Further calls to `initCrypto` are ignored.');
    return;
  }
  const foundationModules = await initFoundation();
  setFoundationModules(foundationModules);
};
