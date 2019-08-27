import { Buffer as NodeBuffer } from 'buffer/';

import { createDataToUint8ArrayFunction } from './dataToUint8Array';
import { createToBufferFunction } from './toBuffer';

export { Buffer } from 'buffer/';

export const dataToUint8Array = createDataToUint8ArrayFunction(NodeBuffer);
export const toBuffer = createToBufferFunction(NodeBuffer);
