var KeysTypesEnum = require('../lib/keys-types-enum');
var IdentityTypes = require('../lib/identity-types');
var generateKeyPair = require('./generate-key-pair');
var encrypt = require('./encrypt');
var encryptStringToBase64 = require('./encrypt-string-to-base64');
var decrypt = require('./decrypt');
var decryptStringFromBase64 = require('./decrypt-string-from-base64');
var sign = require('./sign');
var verify = require('./verify');
var generateValidationToken = require('./generate-validation-token');

module.exports = {
	KeysTypesEnum: KeysTypesEnum,
	IdentityTypesEnum,: IdentityTypes,
	generateKeyPair: generateKeyPair,
	encrypt: encrypt,
	encryptStringToBase64: encryptStringToBase64,
	decrypt: decrypt,
	decryptStringFromBase64: decryptStringFromBase64,
	sign: sign,
	verify: verify,
	generateValidationToken: generateValidationToken
};
