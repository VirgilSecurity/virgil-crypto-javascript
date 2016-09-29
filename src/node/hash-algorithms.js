var VirgilCrypto = require('../../virgil_js.node');

module.exports = {
	SHA1: VirgilCrypto.VirgilHash.Algorithm_SHA1,
	SHA224: VirgilCrypto.VirgilHash.Algorithm_SHA224,
	SHA256: VirgilCrypto.VirgilHash.Algorithm_SHA256,
	SHA384: VirgilCrypto.VirgilHash.Algorithm_SHA384,
	SHA512: VirgilCrypto.VirgilHash.Algorithm_SHA512
};
