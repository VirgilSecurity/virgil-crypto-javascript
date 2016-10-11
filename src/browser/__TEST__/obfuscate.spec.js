import { VirgilCrypto, Buffer } from '../../../browser';

describe('obfuscate', function () {
	it('it obfuscates strings', function () {
		var o1 = VirgilCrypto.obfuscate(Buffer.from('Obfuscate me', 'utf8'), Buffer.from('salt', 'utf8'));
		var o2 = VirgilCrypto.obfuscate(Buffer.from('Obfuscate me', 'utf8'), Buffer.from('salt', 'utf8'));
		expect(Buffer.isBuffer(o1)).toBe(true);
		expect(Buffer.isBuffer(o2)).toBe(true);
		expect(o1.equals(o2)).toBe(true);
	});

	it('different salt -> different result', function () {
		var o1 = VirgilCrypto.obfuscate(Buffer.from('Obfuscate me', 'utf8'), Buffer.from('salt 1', 'utf8'));
		var o2 = VirgilCrypto.obfuscate(Buffer.from('Obfuscate me', 'utf8'), Buffer.from('salt 2', 'utf8'));
		expect(Buffer.isBuffer(o1)).toBe(true);
		expect(Buffer.isBuffer(o2)).toBe(true);
		expect(o1.equals(o2)).not.toBe(true);
	});
});

