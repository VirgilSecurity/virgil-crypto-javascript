import { initBaseCrypto } from '@virgilsecurity/base-crypto';
import initFoundation from '<%= foundation %>';

export * from '@virgilsecurity/base-crypto';
export * from '@virgilsecurity/sdk-crypto';

export const initCrypto = () => initFoundation().then(initBaseCrypto);
