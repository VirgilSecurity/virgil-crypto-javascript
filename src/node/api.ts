import * as lib from '../../virgil_crypto_node.node';
import { IVirgilCryptoApi, createCryptoApi } from '../common';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
