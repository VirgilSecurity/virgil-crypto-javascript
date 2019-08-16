import { Buffer as NodeBuffer } from 'buffer/';

import { createDataToUint8ArrayFunction } from './dataToUint8Array';

export { Buffer } from 'buffer/';

export * from './types';

export const dataToUint8Array = createDataToUint8ArrayFunction(NodeBuffer);
