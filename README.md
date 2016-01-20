# JavaScript Crypto Library

<a href="https://virgilsecurity.com"><img width="230px" src="https://github.com/VirgilSecurity/virgil-net/blob/master/logo.png" align="left" hspace="10" vspace="6"></a>

Virgil is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and all the necessary infrastructure to enable seamless, end-to-end encryption for any application, platform or device. Get in touch with us to get preview access to our key infrastructure.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated). In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end. Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

- [Installation](#installation)
    - [NPM](#npm)
    - [Bower](#bower)
    - [CDN](#cdn)
- [Initialization](#initialization)
    - [Node](#node)
    - [Browsers](#browsers)
- [Generate Key Pair](#generate-key-pair)
- [Encrypt/Decrypt data](#encryptdecrypt-data)
    - [Encrypt/Decrypt data using password](#encryptdecrypt-data-using-password)
    - [Async (using web workers) Encrypt/Decrypt data using password](#async-using-web-workers-encryptdecrypt-data-using-password)
    - [Encrypt/Decrypt data using Key](#encryptdecrypt-data-using-key)
    - [Encrypt/Decrypt data using Key with password](#encryptdecrypt-data-using-key-with-password)
    - [Encrypt/Decrypt data using Key with password for multiple recipients](#encryptdecrypt-data-using-key-with-password-for-multiple-recipients)
    - [Async (using web workers) Encrypt/Decrypt data using Key with password](#async-using-web-workers-encryptdecrypt-data-using-key-with-password)
    - [Async (using web workers) Encrypt/Decrypt data using Key with password for multiple recipients](#async-using-web-workers-encryptdecrypt-data-using-key-with-password-for-multiple-recipients)
    - [Encrypt/Decrypt data using Key without password](#encryptdecrypt-data-using-key-without-password)
    - [Async (using web workers) Encrypt/Decrypt data using Key without password](#async-using-web-workers-encryptdecrypt-data-using-key-without-password)
- [Sign and Verify data using Key](#sign-and-verify-data-using-key)
    - [Sign and Verify data using Key with password](#sign-and-verify-data-using-key-with-password)
- [Async (using web workers) Sign and Verify data using Key with password.](#async-using-web-workers-sign-and-verify-data-using-key-with-password)
  
## Installation

### NPM

```sh
npm install virgil-crypto
```

### Bower
```sh
bower install virgil-crypto
```

### CDN
```html
<script src="https://cdn.virgilsecurity.com/packages/javascript/crypto/latest/virgil-crypto.min.js"></script>
```

## Initialization

### Node

```javascript
var virgilCrypto = requre('virgil-crypto');
```

### Browsers

```javascript
var virgilCrypto = window.VirgilCrypto;
```

## Generate Key Pair

The following code example creates a new public/private key pair.

```javascript
var keyPair = virgilCrypto.generateKeyPair();
console.log('Key pair without password: ', keyPair);
```

You can also generate a key pair with an encrypted private key just using one of the overloaded constructors.

```javascript
var keyPairRsa2048 = virgilCrypto.generateKeyPair(virgilCrypto.KeysTypesEnum.rsa2048);
console.log('Key pair rsa2048 without password: ', keyPairRsa2048);

var KEY_PASSWORD = 'password';
var keyPairWithPassword = virgilCrypto.generateKeyPair(KEY_PASSWORD);
console.log('Key pair with password: ', keyPairWithPassword);


var KEY_PASSWORD = 'password';
var keyPairWithPasswordAndSpecificType = virgilCrypto.generateKeyPair(KEY_PASSWORD, virgilCrypto.KeysTypesEnum.rsa2048);
console.log('Key pair rsa2048 with password: ', keyPairWithPasswordAndSpecificType);
```

In the example below you can see a simply generated public/private keypair without a password.

```
-----BEGIN PUBLIC KEY-----
MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEWIH2SohavmLdRwEJ/VWbFcWr
rU+g7Z/BkI+E1L5JF7Jlvi1T1ed5P0/JCs+K0ZBM/0hip5ThhUBKK2IMbeFjS3Oz
zEsWKgDn8j3WqTb8uaKIFWWG2jEEnU/8S81Bgpw6CyxbCTWoB+0+eDYO1pZesaIS
Tv6dTclx3GljHpFRdZQ=
-----END PUBLIC KEY-----

-----BEGIN EC PRIVATE KEY-----
MIHaAgEBBEAaKrInIcjTeBI6B0mX+W4gMpu84iJtlPxksCQ1Dv+8iM/lEwx3nWWf
ol6OvLkmG/qP9RqyXkTSCW+QONiN9JCEoAsGCSskAwMCCAEBDaGBhQOBggAEWIH2
SohavmLdRwEJ/VWbFcWrrU+g7Z/BkI+E1L5JF7Jlvi1T1ed5P0/JCs+K0ZBM/0hi
p5ThhUBKK2IMbeFjS3OzzEsWKgDn8j3WqTb8uaKIFWWG2jEEnU/8S81Bgpw6Cyxb
CTWoB+0+eDYO1pZesaISTv6dTclx3GljHpFRdZQ=
-----END EC PRIVATE KEY-----
```

Here is what an encrypted private key looks like:

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBKTA0BgoqhkiG9w0BDAEDMCYEIJjDIF2KRj7u86Up1ZB4yHHKhqMg5C/OW2+F
mG5gpI+3AgIgAASB8F39JXRBTK5hyqEHCLcCTbtLKijdNH3t+gtCrLyMlfSfK49N
UTREjF/CcojkyDVs9M0y5K2rTKP0S/LwUWeNoO0zCT6L/zp/qIVy9wCSAr+Ptenz
MR6TLtglpGqpG4bhjqLNR2I96IufFmK+ZrJvJeZkRiMXQSWbPavepnYRUAbXHXGB
a8HWkrjKPHW6KQxKkotGRLcThbi9cDtH+Cc7FvwT80O7qMyIFQvk8OUJdY3sXWH4
5tol7pMolbalqtaUc6dGOsw6a4UAIDaZhT6Pt+v65LQqA34PhgiCxQvJt2UOiPdi
SFMQ8705Y2W1uTexqw==
-----END ENCRYPTED PRIVATE KEY-----
```

## Encrypt/Decrypt data

The procedure for encrypting and decrypting the data is simple. For example:

If you want to encrypt the data to Bob, you encrypt it using Bob's public key (which you can get from the Public Keys Service), and Bob decrypts it with his private key. If Bob wants to encrypt some data to you, he encrypts it using your public key, and you decrypt it with your private key.

Crypto Library allows to encrypt the data for several types of recipient's user data like public key and password. This means that you can encrypt the data with some password or with a public key generated with the Crypto Library.

### Encrypt/Decrypt data using password

> Initial data must be passed as String or [Buffer](https://github.com/feross/buffer)

> Encrypted data will be returned as [Buffer](https://github.com/feross/buffer)

```javascript
var INITIAL_DATA = 'data to be encrypted';
var PASSWORD = 'password';

var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, PASSWORD);
var decryptedData = virgilCrypto.decrypt(encryptedData, PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Async (using web workers) Encrypt/Decrypt data using password

> Browsers only!

```javascript
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

### Encrypt/Decrypt data using Key

> Initial data must be passed as String or [Buffer](https://github.com/feross/buffer)

> Encrypted data will be returned as [Buffer](https://github.com/feross/buffer)

### Encrypt/Decrypt data using Key with password

```javascript
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

var keyPair = virgilCrypto.generateKeyPair(KEY_PASSWORD);
var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var decryptedData = virgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey, KEY_PASSWORD);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Encrypt/Decrypt data using Key with password for multiple recipients

```javascript
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

### Async (using web workers) Encrypt/Decrypt data using Key with password

> Browsers only!

```javascript
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

### Async (using web workers) Encrypt/Decrypt data using Key with password for multiple recipients

> Browsers only!

```javascript
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

### Encrypt/Decrypt data using Key without password

```javascript
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

var keyPair = virgilCrypto.generateKeyPair();
var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var decryptedData = virgilCrypto.decrypt(encryptedData, RECIPIENT_ID, keyPair.privateKey);

console.log('Encrypted data: ' + encryptedData);
console.log('Decrypted data: ' + decryptedData.toString());
```

### Async (using web workers) Encrypt/Decrypt data using Key without password

> Browsers only!

```javascript
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

Cryptographic digital signatures use public key algorithms to provide data integrity. When you sign the data with a digital signature, someone else can verify the signature and can prove that the data originated from you and was not altered after you had signed it.

The following example applies a digital signature to a public key identifier.

> Initial data must be passed as String or [Buffer](https://github.com/feross/buffer)

> Encrypted data will be returned as [Buffer](https://github.com/feross/buffer)

### Sign and Verify data using Key with password

```
var KEY_PASSWORD = 'password';
var INITIAL_DATA = 'data to be encrypted';
var RECIPIENT_ID = '<SOME_RECIPIENT_ID>';

var keyPair = virgilCrypto.generateKeyPair(KEY_PASSWORD);
var encryptedData = virgilCrypto.encrypt(INITIAL_DATA, RECIPIENT_ID, keyPair.publicKey);
var sign = virgilCrypto.sign(encryptedData, keyPair.privateKey, KEY_PASSWORD);
```

To verify that the data was signed by a particular party, you need the following information:

*   the public key of the party that signed the data;
*   the digital signature;
*   the data that was signed.

The following example verifies a digital signature which was signed by the sender.

```
var isDataVerified = virgilCrypto.verify(encryptedData, keyPair.publicKey, sign);

console.log('Encrypted data: ' + encryptedData);
console.log('Sign: ' + sign.toString('base64'));
console.log('Is data verified: ' + isDataVerified);
```

## Async (using web workers) Sign and Verify data using Key with password.

> Browsers only!

```
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
