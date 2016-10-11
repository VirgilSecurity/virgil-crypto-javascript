"use strict";
var VirgilCrypto = require('../');
var expect = require('expect');

describe('obfuscate', function () {
	it('should obfuscate data', function () {
		var o1 = VirgilCrypto.obfuscate(new Buffer('obfuscate me'), new Buffer('salt'));
		var o2 = VirgilCrypto.obfuscate(new Buffer('obfuscate me'), new Buffer('salt'));
		expect(Buffer.isBuffer(o1)).toBe(true);
		expect(Buffer.isBuffer(o2)).toBe(true);
		expect(o1.equals(o2)).toBe(true);
	});

	it('should produce different result depending on salt', function () {
		var o1 = VirgilCrypto.obfuscate(new Buffer('obfuscate me'), new Buffer('salt1'));
		var o2 = VirgilCrypto.obfuscate(new Buffer('obfuscate me'), new Buffer('salt2'));
		expect(Buffer.isBuffer(o1)).toBe(true);
		expect(Buffer.isBuffer(o2)).toBe(true);
		expect(o1.equals(o2)).toBe(false);
	});
});
