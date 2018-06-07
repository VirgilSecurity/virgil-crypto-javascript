import { lib } from './asmjs';
import { createCryptoWrapper, createPythiaWrapper } from '../../common';

/**
 * VirgilCrypto wrapper.
 * @hidden
 */
export const cryptoWrapper = createCryptoWrapper(lib);

/**
 * VirgilPythia wrapper.
 * @hidden
 */
export const pythiaWrapper = createPythiaWrapper(lib);
