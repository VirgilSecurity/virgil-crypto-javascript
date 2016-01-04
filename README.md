# JavaScript Crypto Library

- [Generate Key Pair](#generate-key-pair)
- [Encrypt and Decrypt data using password](#encrypt-and-decrypt-data-using-password)
- [Async (using web workers) Encrypt and Decrypt data using password](#async-using-web-workers-encrypt-and-decrypt-data-using-password)
- [Encrypt and Decrypt data using Key](#encrypt-and-decrypt-data-using-key)
  - [Encrypt and Decrypt data using Key with password](#encrypt-and-decrypt-data-using-key-with-password)
  - [Encrypt and Decrypt data using Key with password for multiple recipients](#encrypt-and-decrypt-data-using-key-with-password-for-multiple-recipients)
- [Async (using web workers) Encrypt and Decrypt data using Key with password](#async-using-web-workers-encrypt-and-decrypt-data-using-key-with-password)
- [Async (using web workers) Encrypt and Decrypt data using Key with password for multiple recipients](#async-using-web-workers-encrypt-and-decrypt-data-using-key-with-password-for-multiple-recipients)
  - [Encrypt and Decrypt data using Key without password](#encrypt-and-decrypt-data-using-key-without-password)
- [Async (using web workers) Encrypt and Decrypt data using Key without password](#async-using-web-workers-encrypt-and-decrypt-data-using-key-without-password)
- [Sign and Verify data using Key](#sign-and-verify-data-using-key)
  - [Sign and Verify data using Key with password](#sign-and-verify-data-using-key-with-password)
- [Async (using web workers) Sign and Verify data using Key with password](#async-using-web-workers-sign-and-verify-data-using-key-with-password)
  
## Generate Key Pair

```javascript
var virgilCrypto = window.VirgilCrypto;

var keyPair = virgilCrypto.generateKeyPair();
console.log('Key pair without password: ', keyPair);

var keyPairRsa2048 = virgilCrypto.generateKeyPair('', virgilCrypto.KeysTypesEnum.rsa2048);
console.log('Key pair rsa2048 without password: ', keyPairRsa2048);

var KEY_PASSWORD = 'password';
var keyPairWithPassword = virgilCrypto.generateKeyPair(KEY_PASSWORD);
console.log('key pair with password: ', keyPairWithPassword);
```

## Encrypt and Decrypt data using password

> Initial data must be passed as String or [Buffer](https://github.com/feross/buffer)

> Encrypted data will be returned as [Buffer](https://github.com/feross/buffer)

```javascript
var virgilCrypto = window.VirgilCrypto;
var INITIAL_DATA = 'data to be encrypted';
var PASSWORD = 'password';

var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, PASSWORD);
var decryptedData = virgilCrypto.decrypt(encryptedData, PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

## Async (using web workers) Encrypt and Decrypt data using password

```javascript
var virgilCrypto = window.VirgilCrypto;
var INITIAL_DATA = 'data to be encrypted';
var PASSWORD = 'password';

virgilCrypto.encryptAsync(INITIAL_DATA, PASSWORD)
  .then(function(encryptedData) {
    console.log('Encrypted data: ' + encryptedData);

    virgilCrypto.decryptAsync(encryptedData, PASSWORD)
      .then(function(decryptedData) {
        console.log('Decrypted data: ' + decryptedData.toString());
      });
  });
```

## Encrypt and Decrypt data using Key

> Initial data must be passed as String or [Buffer](https://github.com/feross/buffer)

> Encrypted data will be returned as [Buffer](https://github.com/feross/buffer)

### Encrypt and Decrypt data using Key with password

```javascript
var virgilCrypto = window.VirgilCrypto;
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

var keyPair = virgilCrypto.generateKeyPair(KEY_PASSWORD);
var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var decryptedData = virgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Encrypt and Decrypt data using Key with password for multiple recipients

```javascript
var virgilCrypto = window.VirgilCrypto;
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

var keyPair = virgilCrypto.generateKeyPair(KEY_PASSWORD);
var recipientsList = [{ recipientId: RECIPIENT_ID, publicKey: keyPair.publicKey }];
var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, recipientsList);
var decryptedData = virgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

## Async (using web workers) Encrypt and Decrypt data using Key with password

```javascript
var virgilCrypto = window.VirgilCrypto;
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

virgilCrypto.generateKeyPairAsync(KEY_PASSWORD)
  .then(function(keyPair) {
    virgilCrypto.encryptAsync(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        virgilCrypto.decryptAsync(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD)
          .then(function(decryptedData) {
            console.log('Decrypted data: ' + decryptedData.toString());
          });
      });
  });
```

## Async (using web workers) Encrypt and Decrypt data using Key with password for multiple recipients

```javascript
var virgilCrypto = window.VirgilCrypto;
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

virgilCrypto.generateKeyPairAsync(KEY_PASSWORD)
  .then(function(keyPair) {
    var recipientsList = [{ recipientId: RECIPIENT_ID, publicKey: keyPair.publicKey }];
    
    virgilCrypto.encryptAsync(INITIAL_DATA, recipientsList)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        virgilCrypto.decryptAsync(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD)
          .then(function(decryptedData) {
            console.log('Decrypted data: ' + decryptedData.toString());
          });
      });
  });
```

### Encrypt and Decrypt data using Key without password

```javascript
var virgilCrypto = window.VirgilCrypto;
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

var keyPair = virgilCrypto.generateKeyPair();
var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var decryptedData = virgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

## Async (using web workers) Encrypt and Decrypt data using Key without password

```javascript
var virgilCrypto = window.VirgilCrypto;
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

virgilCrypto.generateKeyPairAsync()
  .then(function(keyPair) {
    virgilCrypto.encryptAsync(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        virgilCrypto.decryptAsync(encryptedData, RECIPIENT_ID, keyPair.privateKey)
          .then(function(decryptedData) {
            console.log('Decrypted data: ' + decryptedData.toString());
          });
      });
  });
```

## Sign and Verify data using Key

> Initial data must be passed as String or [Buffer](https://github.com/feross/buffer)

> Encrypted data will be returned as [Buffer](https://github.com/feross/buffer)

### Sign and Verify data using Key with password

```javascript
var virgilCrypto = window.VirgilCrypto;
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

var keyPair = virgilCrypto.generateKeyPair(KEY_PASSWORD);
var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var sign = virgilCrypto.sign(encryptedData, keyPair.privateKey, KEY_PASSWORD);
var isDataVerified = virgilCrypto.verify(encryptedData, keyPair.publicKey, sign);

console.log('Encrypted data: ' + encryptedData);
console.log('Sign: ' + sign.toString('base64'));
console.log('Is data verified: ' + isDataVerified);
```

## Async (using web workers) Sign and Verify data using Key with password

```javascript
var virgilCrypto = window.VirgilCrypto;
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

virgilCrypto.generateKeyPairAsync(KEY_PASSWORD)
  .then(function(keyPair) {
    virgilCrypto.encryptAsync(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        virgilCrypto.signAsync(encryptedData, keyPair.privateKey, KEY_PASSWORD)
          .then(function(sign) {
            console.log('Sign: ' + sign.toString('base64'));

            virgilCrypto.verifyAsync(encryptedData, keyPair.publicKey, sign)
              .then(function(isDataVerified) {
                console.log('Is data verified: ' + isDataVerified);
              });
          });
      });
  });
```
