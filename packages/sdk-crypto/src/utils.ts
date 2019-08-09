import { Data } from '@virgilsecurity/base-crypto';

export const prepareData = (value: Uint8Array | string, encoding: string): Data => {
  if (typeof value === 'string') {
    return { value, encoding } as Data;
  }
  return value;
};
