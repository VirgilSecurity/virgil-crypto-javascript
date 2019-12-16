import { expect } from 'chai';

import { memoizePromise } from '../memoizePromise';

describe('memoizePromise', () => {
  it('returns memoized promise', async () => {
    const fn1 = () => Promise.resolve();
    const fn2 = () => Promise.resolve();
    const memoizedPromise1 = memoizePromise(fn1);
    const memoizedPromise2 = memoizePromise(fn2);
    const result1 = memoizedPromise1();
    const result2 = memoizedPromise2();
    const result3 = memoizedPromise1();
    const result4 = memoizedPromise2();
    expect(result1).not.to.equal(result2);
    expect(result1).to.equal(result3);
    expect(result2).to.equal(result4);
  });
});
