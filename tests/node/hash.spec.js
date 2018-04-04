"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

describe('hash', function () {
	it('should hash data', function () {
		var hash1 = VirgilCrypto.hash(new Buffer('Hash me'));
		var hash2 = VirgilCrypto.hash(new Buffer('Hash me'));
		expect(Buffer.isBuffer(hash1)).toBe(true);
		expect(Buffer.isBuffer(hash2)).toBe(true);
		expect(hash1.equals(hash2)).toBe(true);
	});

	it('should produce different result depending on algorithm', function () {
		var hash1 = VirgilCrypto.hash(new Buffer('Hash me'), VirgilCrypto.HashAlgorithm.SHA256);
		var hash2 = VirgilCrypto.hash(new Buffer('Hash me'), VirgilCrypto.HashAlgorithm.SHA384);
		expect(hash1.equals(hash2)).toBe(false);
	});
});
