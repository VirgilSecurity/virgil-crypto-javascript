var _ = require('lodash');
var uuid = require('node-uuid');
var sign = require('./sign');
var IdentityTypes = require('../lib/identity-types');

/**
 * Generate validation token
 */
module.exports = function generateValidationToken (identityValue, identityType, privateKey, privateKeyPassword) {
	if (!_.isString(identityValue)) {
		throw new TypeError('identityValue must be a string');
	}

	if (!_.isString(privateKey)) {
		throw new TypeError('privateKey msut be string');
	}

	var uid = uuid.v4();
	var signature = sign(uid + identityType + identityValue, privateKey, privateKeyPassword);
	var validationToken = Buffer.concat([new Buffer(uid), new Buffer('.'), signature]);
	return validationToken.toString('base64');
};
