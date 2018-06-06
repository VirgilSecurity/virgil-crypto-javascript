import * as lib from '../../../virgil_crypto_node.node';
import { createCryptoApi, createPythiaWrapper, IVirgilCryptoApi } from '../../common';

export const cryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
export const pythiaWrapper = createPythiaWrapper(lib);
