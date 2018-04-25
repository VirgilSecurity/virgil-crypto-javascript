import { lib } from './asmjs';
import { IVirgilCryptoApi, createCryptoApi } from '../common';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
