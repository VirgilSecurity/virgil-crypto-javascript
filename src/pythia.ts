import { makeVirgilCryptoClass, VirgilCryptoClass } from './makeVirgilCryptoClass';
import { cryptoWrapper } from './pythia/node/wrapper';

export { KeyPairType, HashAlgorithm } from './common';
export { VirgilAccessTokenSigner } from './VirgilAccessTokenSigner';
export { VirgilPrivateKeyExporter } from './VirgilPrivateKeyExporter';
export { VirgilCardCrypto } from './VirgilCardCrypto';

export { encoding } from './utils/encoding';

export const VirgilCrypto: VirgilCryptoClass = makeVirgilCryptoClass(cryptoWrapper);
export { VirgilPythiaCrypto } from './VirgilPythiaCrypto';
