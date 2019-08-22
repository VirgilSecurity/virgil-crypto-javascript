export const createToBufferFunction = (NodeBuffer: any) => (
  array: Uint8Array
) => {
  let buffer = NodeBuffer.from(array.buffer);
  if (array.byteLength !== array.buffer.byteLength) {
    buffer = buffer.slice(array.byteOffset, array.byteOffset + array.byteLength);
  }
  return buffer;
};
