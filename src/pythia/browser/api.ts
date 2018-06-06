import { lib } from './asmjs';
import { createCryptoApi, createPythiaWrapper, IVirgilCryptoApi } from '../../common';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
export const pythiaWrapper = createPythiaWrapper(lib);
