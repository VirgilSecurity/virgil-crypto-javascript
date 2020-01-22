import { NodeBuffer } from '@virgilsecurity/data-utils';

export const DATA_SIGNATURE_KEY = NodeBuffer.from('VIRGIL-DATA-SIGNATURE', 'utf8');

export const DATA_SIGNER_ID_KEY = NodeBuffer.from('VIRGIL-DATA-SIGNER-ID', 'utf8');

export const PADDING_LEN = 160;

export const MIN_GROUP_ID_BYTE_LENGTH = 10;
