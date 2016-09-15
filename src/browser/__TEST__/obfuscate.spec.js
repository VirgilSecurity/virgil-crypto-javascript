import { VirgilCrypto } from '../../../browser';

describe('obfuscate', function () {
	it('it obfuscates strings', function () {
		var o1 = VirgilCrypto.obfuscate('Obfuscate me', 'salt');
		var o2 = VirgilCrypto.obfuscate('Obfuscate me', 'salt');
		expect(typeof o1).toEqual('string');
		expect(o1).toEqual(o2);
	});

	it('different salt -> different result', function () {
		var o1 = VirgilCrypto.obfuscate('Obfuscate me', 'salt 1');
		var o2 = VirgilCrypto.obfuscate('Obfuscate me', 'salt 2');
		expect(typeof o1).toEqual('string');
		expect(typeof o2).toEqual('string');
		expect(o1).not.toEqual(o2);
	});
});

