import { lib } from './lib';
import { IVirgilCryptoApi } from '../common/IVirgilCryptoApi';
import { createCryptoApi } from '../common/createCryptoApi';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
