import * as lib from '../../../virgil_crypto_node.node';
import { IVirgilCryptoApi, IVirgilPythiaCryptoApi, createCryptoApi, createPythiaCryptoApi } from '../../common';

const virgilCryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
const pythiaApi = createPythiaCryptoApi(lib);

export const cryptoApi: IVirgilCryptoApi & { pythia: IVirgilPythiaCryptoApi } = {
	...virgilCryptoApi,
	pythia: pythiaApi
};

