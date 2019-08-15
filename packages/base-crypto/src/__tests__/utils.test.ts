import { expect } from 'chai';
import { Buffer as NodeBuffer } from 'buffer';

import { dataToUint8Array } from '../utils';

describe('utils', () => {
  describe('dataToUint8Array', () => {
    it('returns Uint8Array based on a string that was converted to it using defaultEncoding', () => {
      const data = 'data';
      const result = dataToUint8Array(data, 'utf8');
      const expected = NodeBuffer.from(data, 'utf8');
      expect(expected.equals(result)).to.be.true;
    });

    it('returns Uint8Array based on a string that was converted to it using default encoding (utf-8)', () => {
      const data = 'data';
      const result = dataToUint8Array(data);
      const expected = NodeBuffer.from(data, 'utf8');
      expect(expected.equals(result)).to.be.true;
    });

    it('returns the same Uint8Array if argument is an instance of Uint8Array', () => {
      const data = new Uint8Array(0);
      const result = dataToUint8Array(data);
      expect(result === result).to.be.true;
    });

    it('throws if first argument is not a string / Data object / Uint8Array', () => {
      const error = () => {
        // @ts-ignore
        dataToUint8Array(123);
      };
      expect(error).to.throw;
    });

    it('throws if Data object is invalid', () => {
      const error = () => {
        // @ts-ignore
        dataToUint8Array({ value: 123, encoding: 'utf8' });
      };
      expect(error).to.throw;
    });
  });
});
