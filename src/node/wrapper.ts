import * as lib from '../../virgil_crypto_node.node';
import { createCryptoWrapper } from '../common';

/**
 * Object implementing the VirgilCrypto Node.js API.
 * @hidden
 */
export const cryptoWrapper = createCryptoWrapper(lib);
