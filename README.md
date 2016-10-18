# JavaScript Crypto Library [![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript) [![npm](https://img.shields.io/npm/v/virgil-crypto.svg)](https://www.npmjs.com/package/virgil-crypto)

JavaScript wrapper of [Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) for modern browsers and Node.js.

- [Install](#install)
- [Generate Keys](#generate-keys)
- [Encrypt/Decrypt Data](#encryptdecrypt-data)
    - [Using Password](#using-password)
    - [Async (using web workers) Using Password](#async-using-web-workers-using-password)
    - [Using Key](#using-key)
    - [Using Key with Password](#using-key-with-password)
    - [Using Key with Password for Multiple Recipients](#using-key-with-password-for-multiple-recipients)
    - [Async (using web workers) Using Key with Password](#async-using-web-workers-using-key-with-password)
    - [Async (using web workers) Using Key with Password for Multiple Recipients](#async-using-web-workers-using-key-with-password-for-multiple-recipients)
    - [Using Key without Password](#using-key-without-password)
    - [Async (using web workers) Using Key without Password](#async-using-web-workers-using-key-without-password)
- [Sign and Verify Data Using Key](#sign-and-verify-data-using-key)
    - [With Password](#with-password)
    - [Async (using web workers) with Password](#async-using-web-workers-with-password)
- [Hashing](#hashing)
- [Key Pair Utils](#key-pair-utils)
- [Source code](#source-code)
- [Resources](#resources)
- [License](#license)
- [Contacts](#contacts)
  
## Install

### NPM

```sh
npm install virgil-crypto@beta
```

### CDN
```html
<script 
src="https://cdn.virgilsecurity.com/packages/javascript/crypto/2.0.0-beta.0/virgil-crypto.min.js" 
crossorigin="anonymous"></script>
```

## Usage

All API functions accept and return bytes as `Buffer`s. In browser [this module](https://github.com/feross/buffer) is used and is available via `VirgilCrypto.Buffer` property. For node.js it's just [Buffer](https://nodejs.org/api/buffer.html)

## Generate Keys

The following code example generates a new public/private key pair and returns it as an object with `privateKey` and `publicKey` members:

```javascript
var keyPair = VirgilCrypto.generateKeyPair();

// {
//	  publicKey: ..., // Buffer with publicKey
//	  privateKey: ... // Buffer with privateKey
// }
```

You can also generate a key pair with encrypted private key by passing the desired password as `Buffer` via options object:
```javascript
var keyPair = VirgilCrypto.generateKeyPair({ 
	password: new Buffer('password') 
});
```
Another option you can provide is the type of keys to generate.
In the table below you can see all types.

| Key Type          | Description                    |
|-------------------|--------------------------------|
| Default      | recommended safest type        |
| RSA_2048     | RSA 2048 bit (not recommended) |
| RSA_3072     | RSA 3072 bit                   |
| RSA_4096     | RSA 4096 bit                   |
| RSA_8192     | RSA 8192 bit                   |
| EC_SECP256R1 | 256-bits NIST curve            |
| EC_SECP384R1 | 384-bits NIST curve            |
| EC_SECP521R1 | 521-bits NIST curve            |
| EC_BP256R1   | 256-bits Brainpool curve       |
| EC_BP384R1   | 384-bits Brainpool curve       |
| EC_BP512R1   | 512-bits Brainpool curve       |
| EC_SECP256K1 | 256-bits "Koblitz" curve       |
| FAST_EC_X25519 | Curve25519					|
| FAST_EC_ED25519 | Ed25519						|



```javascript
var keyPairCurve25519 = VirgilCrypto.generateKeyPair({ 
	type: VirgilCrypto.KeysTypesEnum.FAST_EC_X25519 
});

var KEY_PASSWORD = new Buffer('password');
var keyPairWithPasswordAndSpecificType = VirgilCrypto.generateKeyPair({
	password: KEY_PASSWORD, 
	type: VirgilCrypto.KeysTypesEnum.RSA_2048
});
```

## Encrypt/Decrypt data

The procedure for encrypting and decrypting the data is simple. For example:

If you want to encrypt the data to Bob, you encrypt it using Bob's public key, and Bob decrypts it with his private key. If Bob wants to encrypt some data to you, he encrypts it using your public key, and you decrypt it with your private key.

Crypto Library allows to encrypt the data for several types of recipient's user data like public key and password. This means that you can encrypt the data with some password or with a public key generated with the Crypto Library.

### Using Password

```javascript
var INITIAL_DATA = new Buffer('data to be encrypted');
var PASSWORD = new Buffer('password');

var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, PASSWORD);
var decryptedData = VirgilCrypto.decrypt(encryptedData, PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Async (using web workers) Using Password

> Only for browsers.

```javascript
var INITIAL_DATA = new VirgilCrypto.Buffer('data to be encrypted');
var PASSWORD = new VirgilCrypto.Buffer('password');

VirgilCrypto.encryptAsync(INITIAL_DATA, PASSWORD)
  .then(function(encryptedData) {
    console.log('Encrypted data: ' + encryptedData);

    VirgilCrypto.decryptAsync(encryptedData, PASSWORD)
      .then(function(decryptedData) {
        console.log('Decrypted data: ' + decryptedData.toString());
      });
  });
```

### Using Key with Password

```javascript
var KEY_PASSWORD = new Buffer('password');
var INITIAL_DATA = new Buffer('data to be encrypted');
var RECIPIENT_ID = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair({ password: KEY_PASSWORD });
var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var decryptedData = VirgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Using Key with Password for Multiple Recipients

```javascript
var KEY_PASSWORD = new Buffer('password');
var INITIAL_DATA = new Buffer('data to be encrypted');
var RECIPIENT_ID = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair({ password: KEY_PASSWORD });
var recipientsList = [{ recipientId: RECIPIENT_ID, publicKey: keyPair.publicKey }];
var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, recipientsList);
var decryptedData = VirgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Async (using web workers) Using Key with Password

> Only for browsers.

```javascript
var KEY_PASSWORD = new VirgilCrypto.Buffer('password');
var INITIAL_DATA = new VirgilCrypto.Buffer('data to be encrypted');
var RECIPIENT_ID = new VirgilCrypto.Buffer('<SOME_RECIPIENT_ID>');

VirgilCrypto.generateKeyPairAsync({ password: KEY_PASSWORD })
  .then(function(keyPair) {
    VirgilCrypto.encryptAsync(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        VirgilCrypto.decryptAsync(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD)
          .then(function(decryptedData) {
            console.log('Decrypted data: ' + decryptedData.toString());
          });
      });
  });
```

### Async (using web workers) Using Key with Password for Multiple Recipients

> Only for browsers.

```javascript
var KEY_PASSWORD = new VirgilCrypto.Buffer('password');
var INITIAL_DATA = new VirgilCrypto.Buffer('data to be encrypted');
var RECIPIENT_ID = new VirgilCrypto.Buffer('<SOME_RECIPIENT_ID>');

VirgilCrypto.generateKeyPairAsync({ password: KEY_PASSWORD })
  .then(function(keyPair) {
    var recipientsList = [{ 
    	recipientId: RECIPIENT_ID, 
    	publicKey: keyPair.publicKey 
    }];
    
    VirgilCrypto.encryptAsync(INITIAL_DATA, recipientsList)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        VirgilCrypto.decryptAsync(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD)
          .then(function(decryptedData) {
            console.log('Decrypted data: ' + decryptedData.toString());
          });
      });
  });
```

### Using Key without Password

```javascript
var INITIAL_DATA = new Buffer('data to be encrypted');
var RECIPIENT_ID = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair();
var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var decryptedData = VirgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Async (using web workers) Using Key without Password

> Only for browsers.

```javascript
var INITIAL_DATA = new VirgilCrypto.Buffer('data to be encrypted');
var RECIPIENT_ID = new VirgilCrypto.Buffer('<SOME_RECIPIENT_ID>');

VirgilCrypto.generateKeyPairAsync()
  .then(function(keyPair) {
    VirgilCrypto.encryptAsync(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        VirgilCrypto.decryptAsync(encryptedData, RECIPIENT_ID, keyPair.privateKey)
          .then(function(decryptedData) {
            console.log('Decrypted data: ' + decryptedData.toString());
          });
      });
  });
```

## Sign and Verify Data Using Key

Cryptographic digital signatures use public key algorithms to provide data integrity. When you sign the data with a digital signature, someone else can verify the signature and can prove that the data originated from you and was not altered after you had signed it.

The following example applies a digital signature to a public key identifier.

### With Password

```javascript
var KEY_PASSWORD = new Buffer('password');
var INITIAL_DATA = new Buffer('data to be encrypted');
var RECIPIENT_ID = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair({ 
	password: KEY_PASSWORD 
});

var encryptedData = VirgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var sign = VirgilCrypto.sign(encryptedData, keyPair.privateKey, KEY_PASSWORD);
```

To verify that the data was signed by a particular party, you need the following information:

*   the public key of the party that signed the data;
*   the digital signature;
*   the data that was signed.

The following example verifies a digital signature which was signed by the sender.

```javascript
var isDataVerified = VirgilCrypto.verify(encryptedData, sign, keyPair.publicKey);

console.log('Encrypted data: ' + encryptedData);
console.log('Sign: ' + sign.toString('base64'));
console.log('Is data verified: ' + isDataVerified);
```

### Async (using web workers) With Password

> Only for browsers.

```javascript
var KEY_PASSWORD = new VirgilCrypto.Buffer('password');
var INITIAL_DATA = new VirgilCrypto.Buffer('data to be encrypted');
var RECIPIENT_ID = new VirgilCrypto.Buffer('<SOME_RECIPIENT_ID>');

VirgilCrypto.generateKeyPairAsync({ password: KEY_PASSWORD })
  .then(function(keyPair) {
    VirgilCrypto.encryptAsync(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey)
      .then(function(encryptedData) {
        console.log('Encrypted data: ' + encryptedData);

        VirgilCrypto.signAsync(encryptedData, keyPair.privateKey, KEY_PASSWORD)
          .then(function(sign) {
            console.log('Sign: ' + sign.toString('base64'));

            VirgilCrypto.verifyAsync(encryptedData, sign, keyPair.publicKey)
              .then(function(isDataVerified) {
                console.log('Is data verified: ' + isDataVerified);
              });
          });
      });
  });
```


## Hashing

### VirgilCrypto.hash(data, algorithm = VirgilCrypto.HashAlgorithm.SHA256)

Returns cryptographic hash of the message (SHA-256 by default). Possible values for `algorithm` parameter are: SHA1, SHA224, SHA256, SHA384, SHA512.
Use ```VirgilCrypto.HashAlgorithm``` object to get the correct value.

### VirgilCrypto.obfuscate(value, salt, algorithm = VirgilCrypto.HashAlgorithm.SHA384, iterations = 2048)

Returns an obfuscated value derived with PBKDF using the given salt, hash algorithm and number of iterations.


## Key pair utils

### VirgilCrypto.changePrivateKeyPassword(privateKey, oldPassword, newPassword)

Changes the password used to encrypt the private key. Returns private key encrypted with new password.

### VirgilCrypto.decryptPrivateKey(privateKey, privateKeyPassword)

Returns an unencrypted private key value.

### VirgilCrypto.encryptPrivateKey(privateKey, privateKeyPassword)

Returns an encrypted private key value.

### VirgilCrypto.extractPrivateKey(privateKey, privateKeyPassword)

Returns public key computed from private key.

> `privateKeyPassword` parameter is optional. Must be a `Buffer` if provided.

### VirgilCrypto.privateKeyToDER(privateKey, privateKeyPassword)

Returns the private key in DER format.

> `privateKeyPassword` parameter is optional. Must be a `Buffer` if provided.

### VirgilCrypto.publicKeyToDER(publicKey)

Returns the public key in DER format.


## Resources

* [Crypto Library](https://github.com/VirgilSecurity/virgil/blob/master/javascript/crypto-library/readme.md)
* [SDK](https://github.com/VirgilSecurity/virgil/blob/master/javascript/keys-sdk/readme.md)

## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE) for details.

## Contacts
Email: <support@virgilsecurity.com>
