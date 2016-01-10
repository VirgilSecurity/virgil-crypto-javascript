var virgilCrypto = require('../index');

var keysTypesEnum = virgilCrypto.KeysTypesEnum;
var keyPair = virgilCrypto.generateKeyPair('', keysTypesEnum.ecNist192);
var initialData = 'initial data';

console.log('initialData', initialData);

console.log('keyPair', keysTypesEnum.ecNist192, keyPair);

var encryptedData = virgilCrypto.encrypt(initialData, 'password');
console.log('encryptedData', encryptedData);
console.log('encryptedData base64', encryptedData.toString('base64'));

var decryptedData = virgilCrypto.decrypt(encryptedData, 'password');
console.log('decryptedData', decryptedData);
console.log('decryptedData string', decryptedData.toString());
console.log('decryptedData base64', decryptedData.toString('base64'));

var encryptedDataByKey = virgilCrypto.encrypt(initialData, keyPair.publicKey, keyPair.publicKey);
console.log('encryptedDataByKey', encryptedDataByKey);
console.log('encryptedDataByKey base64', encryptedDataByKey.toString('base64'));

var decryptedDataByKey = virgilCrypto.decrypt(encryptedDataByKey, keyPair.publicKey, keyPair.privateKey);
console.log('decryptedDataByKey', decryptedDataByKey);
console.log('decryptedDataByKey', decryptedDataByKey.toString());
console.log('decryptedDataByKey base64', decryptedDataByKey.toString('base64'));

var encryptedDataMulti = virgilCrypto.encrypt(initialData, [{ recipientId: keyPair.publicKey, publicKey: keyPair.publicKey }]);
console.log('encryptedDataMulti', encryptedDataMulti);
console.log('encryptedDataMulti string', encryptedDataMulti.toString());
console.log('encryptedDataMulti base64', encryptedDataMulti.toString('base64'));

var decryptedDataMulti = virgilCrypto.decrypt(encryptedDataMulti, keyPair.publicKey, keyPair.privateKey);
console.log('decryptedDataMulti', decryptedDataMulti);
console.log('decryptedDataMulti string', decryptedDataMulti.toString());
console.log('decryptedDataMulti base64', decryptedDataMulti.toString('base64'));

var sign = virgilCrypto.sign(encryptedDataByKey, keyPair.privateKey);
console.log('sign', sign);
console.log('sign base64', sign.toString('base64'));

var verified = virgilCrypto.verify(encryptedDataByKey, keyPair.publicKey, sign);
console.log('verified', verified);
