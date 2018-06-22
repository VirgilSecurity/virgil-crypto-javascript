import { makeVirgilCryptoClass, VirgilCryptoClass } from './makeVirgilCryptoClass';
import { cryptoWrapper } from './node/wrapper';

export { KeyPairType, HashAlgorithm } from './common';
export { VirgilAccessTokenSigner } from './VirgilAccessTokenSigner';
export { VirgilPrivateKeyExporter } from './VirgilPrivateKeyExporter';
export { VirgilCardCrypto } from './VirgilCardCrypto';

export { encoding } from './utils/encoding';

/**
 * Dynamically generated class implementing the {@link IVirgilCrypto} interface.
 */
export const VirgilCrypto: VirgilCryptoClass = makeVirgilCryptoClass(cryptoWrapper);
