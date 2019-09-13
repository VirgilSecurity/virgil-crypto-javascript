import { expect } from 'chai';

import { Buffer as BrowserBuffer } from 'buffer/';

describe('browser', () => {
  it('exports correct Buffer', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { NodeBuffer } = require('../browser');
    expect(NodeBuffer).to.eql(BrowserBuffer);
  });
});
