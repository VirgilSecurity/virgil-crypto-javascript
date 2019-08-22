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

  it('returns correct buffer respecting the buffer\'s view', () => {
    const data = Buffer.from('data', 'utf8').subarray(0, 1);
    const result = toBuffer(data);
    expect(result).to.eql(Buffer.from('d', 'utf8'));
  });
});
