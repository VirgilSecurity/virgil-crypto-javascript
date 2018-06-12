import { makeVirgilCryptoFactory } from './makeVirgilCryptoFactory';
import { cryptoWrapper } from './node/wrapper';

export { KeyPairType, HashAlgorithm } from './common';
export { VirgilAccessTokenSigner } from './VirgilAccessTokenSigner';
export { VirgilPrivateKeyExporter } from './VirgilPrivateKeyExporter';
export { VirgilCardCrypto } from './VirgilCardCrypto';

export { encoding } from './utils/encoding';

/**
 * Factory function producing objects implementing the {@link VirgilCrypto} interface.
 */
export const createVirgilCrypto = makeVirgilCryptoFactory(cryptoWrapper);
