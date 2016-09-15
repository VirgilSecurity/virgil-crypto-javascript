var virgilCrypto = require('../index');

var keysTypesEnum = virgilCrypto.KeysTypesEnum;
var privateKeyPassword = 'veryStrongPa$$0rd';
var initialData = 'initial data';

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

var encryptedStringToBase64Data = virgilCrypto.encryptStringToBase64(initialData, 'password');
console.log('encryptedStringToBase64Data', encryptedStringToBase64Data);
var decryptedStringToBase64Data = virgilCrypto.decryptStringFromBase64(encryptedStringToBase64Data, 'password');
console.log('decryptedStringToBase64Data', decryptedStringToBase64Data);

var encryptedData = virgilCrypto.encrypt(initialData, 'password');
console.log('encryptedData base64', encryptedData.toString('base64'));

var decryptedData = virgilCrypto.decrypt(encryptedData, 'password');
console.log('decryptedData string', decryptedData.toString('utf8'));
console.log('decryptedData base64', decryptedData.toString('base64'));

var encryptedDataByKey = virgilCrypto.encrypt(initialData, keyPair.publicKey, keyPair.publicKey);
console.log('encryptedDataByKey base64', encryptedDataByKey.toString('base64'));

var decryptedDataByKey = virgilCrypto.decrypt(encryptedDataByKey, keyPair.publicKey, keyPair.privateKey, privateKeyPassword);
console.log('decryptedDataByKey', decryptedDataByKey.toString());
console.log('decryptedDataByKey base64', decryptedDataByKey.toString('base64'));

var encryptedDataMulti = virgilCrypto.encrypt(initialData, [{ recipientId: keyPair.publicKey, publicKey: keyPair.publicKey }]);
console.log('encryptedDataMulti base64', encryptedDataMulti.toString('base64'));

var decryptedDataMulti = virgilCrypto.decrypt(encryptedDataMulti, keyPair.publicKey, keyPair.privateKey, privateKeyPassword);
console.log('decryptedDataMulti string', decryptedDataMulti.toString());
console.log('decryptedDataMulti base64', decryptedDataMulti.toString('base64'));

var sign = virgilCrypto.sign(encryptedDataByKey, keyPair.privateKey, privateKeyPassword);
console.log('sign base64', sign.toString('base64'));

var verified = virgilCrypto.verify(encryptedDataByKey, keyPair.publicKey, sign);
console.log('verified', verified);

var verifiedBase64 = virgilCrypto.verify(encryptedDataByKey, keyPair.publicKey, sign.toString('base64'));
console.log('verified sign as base64', verifiedBase64);
