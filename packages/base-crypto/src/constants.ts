import { dataToUint8Array } from './utils';

export const DATA_SIGNATURE_KEY = dataToUint8Array({
  value: 'VIRGIL-DATA-SIGNATURE',
  encoding: 'utf8',
});

export const DATA_SIGNER_ID_KEY = dataToUint8Array({
  value: 'VIRGIL-DATA-SIGNER-ID',
  encoding: 'utf8',
});
