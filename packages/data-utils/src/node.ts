import { createDataToUint8ArrayFunction } from './dataToUint8Array';
import { createToBufferFunction } from './toBuffer';

export const NodeBuffer = global.Buffer;
export const dataToUint8Array = createDataToUint8ArrayFunction(NodeBuffer);
export const toBuffer = createToBufferFunction(NodeBuffer);
