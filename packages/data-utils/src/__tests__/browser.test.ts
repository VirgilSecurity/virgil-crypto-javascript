import { expect } from 'chai';

import { Buffer as BrowserBuffer } from 'buffer/';

describe('browser', () => {
  it('exports correct Buffer', () => {
    const { Buffer } = require('../browser');
    expect(Buffer).to.eql(BrowserBuffer);
  });
});
