import { lib } from './asmjs';
import { IVirgilCryptoApi, IVirgilPythiaCryptoApi, createCryptoApi, createPythiaCryptoApi } from '../../common';

const virgilCryptoApi: IVirgilCryptoApi = createCryptoApi(lib);
const pythiaApi = createPythiaCryptoApi(lib);

export const cryptoApi: IVirgilCryptoApi & { pythia: IVirgilPythiaCryptoApi } = {
	...virgilCryptoApi,
	pythia: pythiaApi
};

