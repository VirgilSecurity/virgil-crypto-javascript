import { expect } from 'chai';

import { Buffer as BrowserBuffer } from 'buffer/';

describe('browser', () => {
  it('exports correct Buffer', () => {
    const { NodeBuffer } = require('../browser');
    expect(NodeBuffer).to.eql(BrowserBuffer);
  });
});
