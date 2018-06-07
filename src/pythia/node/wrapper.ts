import * as lib from '../../../virgil_crypto_node.node';
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
