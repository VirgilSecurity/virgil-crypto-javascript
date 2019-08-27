import { createDataToUint8ArrayFunction } from './dataToUint8Array';
import { createToBufferFunction } from './toBuffer';

const buffer = global.Buffer;
export { buffer as Buffer };

export const dataToUint8Array = createDataToUint8ArrayFunction(buffer);
export const toBuffer = createToBufferFunction(buffer);
