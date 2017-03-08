var Virgil = require('../../virgil_js');
var wrapper = require('../lib/wrapper')(require('./utils'));

wrapper.wrapMethods(Virgil.VirgilTinyCipher.prototype.__proto__);

module.exports = {
	KeyPairType: require('../lib/key-pair-type'),
	HashAlgorithm: require('./hash-algorithms'),
	generateKeyPair: require('./generate-key-pair'),
	encrypt: require('./encrypt'),
	decrypt: require('./decrypt'),
	sign: require('./sign'),
	verify: require('./verify'),
	obfuscate: require('./obfuscate'),
	hash: require('./hash'),
	privateKeyToDER: require('./private-key-to-der'),
	publicKeyToDER: require('./public-key-to-der'),
	extractPublicKey: require('./extract-public-key'),
	changePrivateKeyPassword: require('./change-private-key-password'),
	encryptPrivateKey: require('./encrypt-private-key'),
	decryptPrivateKey: require('./decrypt-private-key'),
	signThenEncrypt: require('./sign-then-encrypt'),
	decryptThenVerify: require('./decrypt-then-verify'),
	VirgilTinyCipher: Virgil.VirgilTinyCipher,
	VirgilCryptoError: require('./virgil-crypto-error')
};
