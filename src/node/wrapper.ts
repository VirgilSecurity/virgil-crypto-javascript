import * as lib from '../../virgil_crypto_node.node';
import { createCryptoWrapper, IVirgilCryptoWrapper } from '../common';

/**
 * Object implementing the VirgilCrypto Node.js API.
 * @hidden
 */
export const cryptoWrapper: IVirgilCryptoWrapper = createCryptoWrapper(lib);
