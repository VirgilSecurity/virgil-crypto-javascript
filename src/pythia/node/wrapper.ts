import * as lib from '../../../virgil_crypto_node.node';
import { createCryptoWrapper, createPythiaWrapper, IVirgilCryptoWrapper } from '../../common';

/**
 * VirgilCrypto wrapper.
 * @hidden
 */
export const cryptoWrapper: IVirgilCryptoWrapper = createCryptoWrapper(lib);

/**
 * VirgilPythia wrapper.
 * @hidden
 */
export const pythiaWrapper = createPythiaWrapper(lib);
