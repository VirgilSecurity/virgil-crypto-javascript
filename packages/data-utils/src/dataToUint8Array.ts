import { Data, StringEncoding } from './types';

export const createDataToUint8ArrayFunction = (NodeBuffer: any) =>
  (data: Data, defaultEncoding?: keyof typeof StringEncoding) => {
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
