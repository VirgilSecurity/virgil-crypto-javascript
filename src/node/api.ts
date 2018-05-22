import * as lib from '../../virgil_crypto_node.node';
import { IVirgilCryptoApi, createCryptoApi } from '../common';

/**
 * Object implementing the VirgilCrypto Node.js API.
 * @hidden
 * @type {IVirgilCryptoApi}
 */
export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
