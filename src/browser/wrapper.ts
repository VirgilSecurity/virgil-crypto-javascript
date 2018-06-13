import { lib } from './asmjs';
import { createCryptoWrapper, IVirgilCryptoWrapper } from '../common';

/**
 * Object implementing the VirgilCrypto Browser API.
 * @hidden
 */
export const cryptoWrapper: IVirgilCryptoWrapper = createCryptoWrapper(lib);
