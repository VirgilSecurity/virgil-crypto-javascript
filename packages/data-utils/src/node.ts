import { createDataToUint8ArrayFunction } from './dataToUint8Array';

export * from './types';

const buffer = global.Buffer;
export { buffer as Buffer };

export const dataToUint8Array = createDataToUint8ArrayFunction(buffer);
