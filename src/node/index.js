var Virgil = require('../../virgil_js');
var wrapper = require('../lib/wrapper')(require('./utils'));
wrapper.wrapPrototype(Virgil, 'VirgilTinyCipher');

module.exports = {
	KeysTypesEnum: require('../lib/keys-types-enum'),
	HashAlgorithm: require('./hash-algorithms'),
	generateKeyPair: require('./generate-key-pair'),
	encrypt: require('./encrypt'),
	decrypt: require('./decrypt'),
	sign: require('./sign'),
	verify: require('./verify'),
	generateValidationToken: require('./generate-validation-token'),
	obfuscate: require('./obfuscate'),
	hash: require('./hash'),
	privateKeyToDER: require('./private-key-to-der'),
	publicKeyToDER: require('./public-key-to-der'),
	extractPublicKey: require('./extract-public-key'),
	changePrivateKeyPassword: require('./change-private-key-password'),
	encryptPrivateKey: require('./encrypt-private-key'),
	decryptPrivateKey: require('./decrypt-private-key'),
	VirgilTinyCipher: Virgil.VirgilTinyCipher
};
