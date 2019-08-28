import { expect } from 'chai';

describe('node', () => {
  it('exports correct Buffer', () => {
    const { NodeBuffer } = require('../node');
    expect(NodeBuffer).to.eql(global.Buffer);
  });
});
