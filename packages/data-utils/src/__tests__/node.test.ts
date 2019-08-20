import { expect } from 'chai';

describe('node', () => {
  it('exports correct Buffer', () => {
    const { Buffer } = require('../node');
    expect(Buffer).to.eql(global.Buffer);
  });
});
