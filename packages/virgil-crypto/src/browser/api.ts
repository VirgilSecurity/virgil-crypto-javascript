import { lib } from './lib';
import { createCryptoApi } from '../common/createCryptoApi';
import { IVirgilCryptoApi } from '../common/IVirgilCryptoApi';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
