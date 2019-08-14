import { Buffer as NodeBuffer } from 'buffer';

import { StringEncoding, Data } from './types';

export const dataToUint8Array = (
  data: Data,
  defaultEncoding?: keyof typeof StringEncoding,
): Uint8Array => {
  if (typeof data === 'string') {
    return NodeBuffer.from(data, defaultEncoding);
  }
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

export const toArray = <T>(val?: T | T[]): T[] => {
  return val == null ? [] : Array.isArray(val) ? val : [val];
};

export const toBuffer = (array: Uint8Array) => NodeBuffer.from(array.buffer);
