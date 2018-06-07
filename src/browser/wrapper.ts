import { lib } from './asmjs';
import { createCryptoWrapper } from '../common';

/**
 * Object implementing the VirgilCrypto Browser API.
 * @hidden
 */
export const cryptoWrapper = createCryptoWrapper(lib);
