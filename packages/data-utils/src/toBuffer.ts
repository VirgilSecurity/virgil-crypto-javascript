import { NodeBuffer } from './types';

export const createToBufferFunction = (NodeBuffer: any) => (
  array: Uint8Array
): NodeBuffer => {
  let buffer = NodeBuffer.from(array.buffer);
  if (array.byteLength !== array.buffer.byteLength) {
    buffer = buffer.slice(array.byteOffset, array.byteOffset + array.byteLength);
  }
  return buffer;
};
