import { CryptoModules } from '@virgilsecurity/base-crypto';

export * from '@virgilsecurity/base-crypto';

export * from '@virgilsecurity/sdk-crypto';

export function initCrypto(): Promise<CryptoModules>;
