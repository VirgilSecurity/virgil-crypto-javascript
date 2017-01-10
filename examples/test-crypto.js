var virgilCrypto = require('../index');

var keysTypesEnum = virgilCrypto.KeyPairTypes;
var privateKeyPassword = new Buffer('veryStrongPa$$0rd');
var initialData = new Buffer('initial data');

var keyPair = virgilCrypto.generateKeyPair({ password: privateKeyPassword });
console.log('Recommended type with password key pair', JSON.stringify(keyPair));

var keyPairDefaultParams = virgilCrypto.generateKeyPair();
console.log('Recommended type, no password key pair', keyPairDefaultParams);

var keyPairPasswordAndType = virgilCrypto.generateKeyPair({
	password: privateKeyPassword,
	type: keysTypesEnum.Default
});
console.log('Default with password key pair', keyPairPasswordAndType);

var keyPairOnlyType = virgilCrypto.generateKeyPair({ type: keysTypesEnum.Default });
console.log('Default, no password key pair', keyPairOnlyType);

try {
	virgilCrypto.generateKeyPair({ type: 'Unsupported type' });
} catch (e) {
	console.log('Trying to generate key pair with unsupported type', e.message);
}

var encryptedData = virgilCrypto.encrypt(initialData, new Buffer('password'));
console.log('encryptedData base64', encryptedData.toString('base64'));

var decryptedData = virgilCrypto.decrypt(encryptedData, new Buffer('password'));
console.log('decryptedData string', decryptedData.toString('utf8'));

var encryptedDataByKey = virgilCrypto.encrypt(initialData, keyPair.publicKey, keyPair.publicKey);
console.log('encryptedDataByKey base64', encryptedDataByKey.toString('base64'));

var decryptedDataByKey = virgilCrypto.decrypt(encryptedDataByKey, keyPair.publicKey, keyPair.privateKey, privateKeyPassword);
console.log('decryptedDataByKey', decryptedDataByKey.toString());

var encryptedDataMulti = virgilCrypto.encrypt(initialData, [{ recipientId: keyPair.publicKey, publicKey: keyPair.publicKey }]);
console.log('encryptedDataMulti base64', encryptedDataMulti.toString('base64'));

var decryptedDataMulti = virgilCrypto.decrypt(encryptedDataMulti, keyPair.publicKey, keyPair.privateKey, privateKeyPassword);
console.log('decryptedDataMulti string', decryptedDataMulti.toString());

var sign = virgilCrypto.sign(encryptedDataByKey, keyPair.privateKey, privateKeyPassword);
console.log('sign base64', sign.toString('base64'));

var verified = virgilCrypto.verify(encryptedDataByKey, sign, keyPair.publicKey);
console.log('verified', verified);
