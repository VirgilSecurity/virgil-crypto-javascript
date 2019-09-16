import { NodeBuffer as BufferType } from './types';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const createToBufferFunction = (NodeBuffer: any) => (array: Uint8Array): BufferType => {
  let buffer = NodeBuffer.from(array.buffer);
  if (array.byteLength !== array.buffer.byteLength) {
    buffer = buffer.slice(array.byteOffset, array.byteOffset + array.byteLength);
  }
  return buffer;
};
