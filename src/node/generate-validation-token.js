var uuid = require('node-uuid');
var sign = require('./sign');
var u = require('./utils');

/**
 * Generate validation token
 */
module.exports = function generateValidationToken (identityValue, identityType, privateKey, privateKeyPassword) {
	privateKeyPassword = privateKeyPassword || new Buffer(0);

	if (typeof identityValue !== 'string') {
		throw new TypeError('"identityValue" argument must be a string');
	}
	u.checkIsBuffer(privateKey, 'privateKey');
	u.checkIsBuffer(privateKeyPassword, 'privateKeyPassword');

	var uid = uuid.v4();
	var signature = sign(new Buffer(uid + identityType + identityValue), privateKey, privateKeyPassword);
	var validationToken = Buffer.concat([new Buffer(uid), new Buffer('.'), new Buffer(signature.toString('base64'))]);
	return validationToken.toString('base64');
};
