import { Buffer as NodeBuffer } from 'buffer';

import { StringEncoding, Data } from './types';

export const dataToUint8Array = (data: Data): Uint8Array => {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (
    typeof data === 'object' &&
    typeof data.value === 'string' &&
    typeof StringEncoding[data.encoding] !== 'undefined'
  ) {
    return NodeBuffer.from(data.value, data.encoding);
  }
  throw new TypeError('Invalid format of Data');
};

export const uint8ArrayOrStringToUint8Array = (
  value: Uint8Array | string,
  encoding: keyof typeof StringEncoding,
) => {
  if (typeof value === 'string') {
    return dataToUint8Array({ value, encoding });
  }
  return value;
};

export const toArray = <T>(val?: T | T[]): T[] => {
  return val == null ? [] : Array.isArray(val) ? val : [val];
};

export const toBuffer = (array: Uint8Array) => NodeBuffer.from(array.buffer);
