import { expect } from 'chai';

import { createToBufferFunction } from '../toBuffer';

describe('toBuffer', () => {
  let toBuffer: ReturnType<typeof createToBufferFunction>;

  before(() => {
    toBuffer = createToBufferFunction(Buffer);
  });

  it('returns correct buffer', () => {
    const data = Buffer.from('data', 'utf8');
    const result = toBuffer(data);
    expect(result.buffer).to.eql(data.buffer);
  });
});
