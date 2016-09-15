var _ = require('lodash');
var VirgilKeyPair = require('../../virgil_js.node').VirgilKeyPair;
var KeysTypesEnum = require('../lib/keys-types-enum');
var u = require('./utils');

function isValidKeysType(keysType) {
	return KeysTypesEnum.hasOwnProperty(keysType);
}

/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keys options.
 * @param {string=} options.password - Private key password (Optional).
 * @param {string=} options.type - Keys type identifier (Optional). If provided must be one of KeysTypesEnum values.
 * @returns {{publicKey: *, privateKey: *}}
 */
module.exports = function generateKeyPair (options) {
	options = options || {};
	var password = options.password || '';
	var keysType = options.type;

	if (keysType && !isValidKeysType(keysType)) {
		throw new TypeError('The value `' + keysType + '` is not a valid type identifier. Must be one of ' +
			_.keys(KeysTypesEnum).join(', ') + ' - use the KeysTypesEnum to get it.');
	}

	if (!_.isString(password)) {
		throw new TypeError('The argument `password` must be a String');
	}
	
	var generate = keysType ?
		VirgilKeyPair.generate.bind(VirgilKeyPair, VirgilKeyPair['Type_' + KeysTypesEnum[keysType]]) :
		VirgilKeyPair.generateRecommended.bind(VirgilKeyPair);


	var virgilKeys = generate(u.stringToByteArray(password));

	return {
		privateKey: u.byteArrayToString(virgilKeys.privateKey()),
		publicKey: u.byteArrayToString(virgilKeys.publicKey())
	};
};
