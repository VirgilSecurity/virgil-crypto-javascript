export const createToBufferFunction = (NodeBuffer: any) => (
  array: Uint8Array
) => NodeBuffer.from(array.buffer);
