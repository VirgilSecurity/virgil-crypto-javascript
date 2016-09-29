"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

describe('hash', function () {
	it('it hashes strings', function () {
		var hash1 = VirgilCrypto.hash('Hash me');
		var hash2 = VirgilCrypto.hash('Hash me');
		expect(Buffer.isBuffer(hash1)).toBe(true);
		expect(Buffer.isBuffer(hash2)).toBe(true);
		expect(hash1.toString('hex')).toEqual(hash2.toString('hex'));
	});

	it('different algorithm -> different result', function () {
		var hash1 = VirgilCrypto.hash('Hash me', VirgilCrypto.HashAlgorithm.SHA256);
		var hash2 = VirgilCrypto.hash('Hash me', VirgilCrypto.HashAlgorithm.SHA384);
		expect(hash1.toString('hex')).toNotEqual(hash2.toString('hex'));
	});
});
