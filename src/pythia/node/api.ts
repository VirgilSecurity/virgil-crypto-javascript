import * as lib from '../../../virgil_crypto_node.node';
import { createCryptoApi, createPythiaCryptoApi, IVirgilCryptoApi, IVirgilPythiaCryptoApi } from '../../common';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
export const pythiaCryptoApi: IVirgilPythiaCryptoApi = createPythiaCryptoApi(lib);
