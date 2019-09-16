import { expect } from 'chai';

describe('node', () => {
  it('exports correct Buffer', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { NodeBuffer } = require('../node');
    expect(NodeBuffer).to.eql(global.Buffer);
  });
});
