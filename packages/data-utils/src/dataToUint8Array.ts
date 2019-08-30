import { Data, StringEncoding } from './types';

export const createDataToUint8ArrayFunction = (NodeBuffer: any) =>
  (data: Data, defaultEncoding?: StringEncoding): Uint8Array => {
    if (typeof data === 'string') {
      if (typeof defaultEncoding === 'string' && !NodeBuffer.isEncoding(defaultEncoding)) {
        throw new TypeError('Invalid default encoding');
      }
      return NodeBuffer.from(data, defaultEncoding);
    }
    if (data instanceof Uint8Array) {
      return data;
    }
    if (
      typeof data === 'object' &&
      typeof data.value === 'string' &&
      typeof NodeBuffer.isEncoding(data.encoding)
    ) {
      return NodeBuffer.from(data.value, data.encoding);
    }
    throw new TypeError('Invalid format of Data');
  };
