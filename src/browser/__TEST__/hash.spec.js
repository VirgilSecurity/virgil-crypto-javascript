import { VirgilCrypto } from '../../../browser';

describe('hash', function () {
	it('it hashes strings', function () {
		var hash1 = VirgilCrypto.hash('Hash me');
		var hash2 = VirgilCrypto.hash('Hash me');
		expect(VirgilCrypto.Buffer.isBuffer(hash1)).toBeTrue();
		expect(VirgilCrypto.Buffer.isBuffer(hash2)).toBeTrue();
		expect(hash1.toString('hex')).toEqual(hash2.toString('hex'));
	});

	it('different algorithm -> different hash', function () {
		var hash256 = VirgilCrypto.hash('Hash me', VirgilCrypto.HashAlgorithm.SHA256);
		var hash384 = VirgilCrypto.hash('Hash me', VirgilCrypto.HashAlgorithm.SHA384);
		expect(VirgilCrypto.Buffer.isBuffer(hash256)).toBeTrue();
		expect(VirgilCrypto.Buffer.isBuffer(hash384)).toBeTrue();
		expect(hash256.toString('hex')).not.toEqual(hash384.toString('hex'));
	});
});
