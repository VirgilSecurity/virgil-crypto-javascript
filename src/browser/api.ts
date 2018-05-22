import { lib } from './asmjs';
import { IVirgilCryptoApi, createCryptoApi } from '../common';

/**
 * Object implementing the VirgilCrypto Browser API.
 * @hidden
 * @type {IVirgilCryptoApi}
 */
export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
