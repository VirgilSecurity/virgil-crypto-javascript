var VirgilKeyPair = require('../../virgil_js.node').VirgilKeyPair;
var KeyPairType = require('../lib/key-pair-type');
var u = require('./utils');

function isValidKeysType(keysType) {
	return KeyPairType.hasOwnProperty(keysType);
}

/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keys options.
 * @param {Buffer=} options.password - Private key password (Optional).
 * @param {string=} options.type - Keys type identifier (Optional). If provided must be one of KeyPairType values.
 * @returns {{publicKey: <Buffer>, privateKey: <Buffer>}}
 */
module.exports = function generateKeyPair (options) {
	options = options || {};
	var password = options.password || new Buffer(0);
	var keysType = options.type;

	if (keysType && !isValidKeysType(keysType)) {
		throw new TypeError('The value `' + keysType + '` is not a valid keys type. Must be one of ' +
			Object.keys(KeyPairType).join(', ') + ' - use KeyPairType.');
	}

	u.checkIsBuffer(password, 'password');

	var generate = keysType ?
		VirgilKeyPair.generate.bind(null, VirgilKeyPair['Type_' + KeyPairType[keysType]]) :
		VirgilKeyPair.generateRecommended;


	var virgilKeys = generate(u.bufferToByteArray(password));

	return {
		privateKey: u.byteArrayToBuffer(virgilKeys.privateKey()),
		publicKey: u.byteArrayToBuffer(virgilKeys.publicKey())
	};
};
