import { VirgilCrypto, Buffer } from '../../../browser';

describe('hash', function () {
	it('it hashes strings', function () {
		var hash1 = VirgilCrypto.hash(Buffer.from('Hash me', 'utf8'));
		var hash2 = VirgilCrypto.hash(Buffer.from('Hash me', 'utf8'));
		expect(Buffer.isBuffer(hash1)).toBe(true);
		expect(Buffer.isBuffer(hash2)).toBe(true);
		expect(hash1.equals(hash2)).toBe(true);
	});

	it('different algorithm -> different hash', function () {
		var hash256 = VirgilCrypto.hash(Buffer.from('Hash me', 'utf8'), VirgilCrypto.HashAlgorithm.SHA256);
		var hash384 = VirgilCrypto.hash(Buffer.from('Hash me', 'utf8'), VirgilCrypto.HashAlgorithm.SHA384);
		expect(VirgilCrypto.Buffer.isBuffer(hash256)).toBe(true);
		expect(VirgilCrypto.Buffer.isBuffer(hash384)).toBe(true);
		expect(hash256.equals(hash384)).not.toBe(true);
	});
});
