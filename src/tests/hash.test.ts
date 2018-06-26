import { cryptoWrapper } from '../node/wrapper';
import { HashAlgorithm } from '../common';

describe('calculateHash', function () {
	it('should produce the same hash for the same data', function () {
		const hash1 = cryptoWrapper.hash(Buffer.from('Hash me'));
		const hash2 = cryptoWrapper.hash(Buffer.from('Hash me'));
		assert.isTrue(hash1.equals(hash2),'same data results in same hash');
	});

	it('should produce different hash for different algorithms', function () {
		const hash1 = cryptoWrapper.hash(Buffer.from('Hash me'), HashAlgorithm.SHA256);
		const hash2 = cryptoWrapper.hash(Buffer.from('Hash me'), HashAlgorithm.SHA384);
		assert.isFalse(hash1.equals(hash2),'same data and different algorithms result in different hashes');
	});
});
