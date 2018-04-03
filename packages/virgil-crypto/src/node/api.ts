import lib from '../../virgil_crypto_node.node';
import { IVirgilCryptoApi } from '../common/IVirgilCryptoApi';
import { createCryptoApi } from '../common/createCryptoApi';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
