# JavaScript Crypto Library [![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript.svg?branch=v2_0)](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript) [![npm](https://img.shields.io/npm/v/virgil-crypto.svg)](https://www.npmjs.com/package/virgil-crypto)

JavaScript wrapper of [Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) 
for modern browsers and Node.js.

- [Install](#install)
- [Usage](#usage)
- [Generate Keys](#generate-keys)
- [Encryption](#encryption)
- [Decryption](#decryption)
- [Signatures](#signatures)
- [Authenticated Encryption](#authenticated-encryption)
- [Hashing](#hashing)
- [Key Pair Utils](#key-pair-utils)
- [Resources](#resources)
- [License](#license)
- [Contacts](#contacts)
  
## Install

### NPM

```sh
npm install virgil-crypto
```

### CDN
```html
<script 
src="https://cdn.virgilsecurity.com/packages/javascript/crypto/2.0.0/virgil-crypto.min.js" 
crossorigin="anonymous"></script>
```

## Usage

All API functions accept and return bytes as `Buffer` objects. In browser 
[this module](https://github.com/feross/buffer) is used and is available via `VirgilCrypto.Buffer` property. 
In Node.js it's native [Buffer](https://nodejs.org/api/buffer.html).

Async versions of functions are implemented using [Web Workers](https://developer.mozilla.org/en-US/docs/Web/API/Worker)
and therefore are only available in the browser. This also means that Chrome and Opera will give an error 
`"Uncaught SecurityError: Script at '[blob url here]' cannot be accessed from origin 'null'."` when you try 
to load VirgilCrypto from `file://` url. It needs to be on a proper domain. 

Async functions are Promise-based. Promise implementation is provided
by [core-js](https://github.com/zloirock/core-js#ecmascript-6-promise).

## Generate Keys

### generateKeyPair(\[options\])

Generates a key pair. Provide `options` to specify the type of keys to generate (see below for the list 
of available types) and\or password to use to encrypt the private key. The keys returned are in PEM format.


#### Arguments

* \[options={}\] (Object): The options object.
* \[options.password\] (Buffer): Password to use to encrypt the private key.
* \[options.type\] (string): Type of keys to generate.


#### Returns

* (Object.\<{privateKey: Buffer, publicKey: Buffer}\>): New key pair.


#### Available Key Pair Types



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

e.g. `VirgilCrypto.KeyPairType.EC_SECP384R1` for 384-bits NIST curve.


#### Examples

Generate a key pair of recommended safest type without encrypting private key: 

```javascript
var keyPair = VirgilCrypto.generateKeyPair();
//{
//   publicKey: ...,  // Buffer with public key
//   privateKey: ...  // Buffer with private key
//}
```

Generate a key pair with encrypted private key and recommended type:

```javascript
var keyPair = VirgilCrypto.generateKeyPair({ 
	password: new VirgilCrypto.Buffer('pa$$w0rd') 
});
```

Generate Curve25519 key pair with encrypted private key:

```javascript
var keyPairCurve25519 = VirgilCrypto.generateKeyPair({ 
	type: VirgilCrypto.KeyPairType.FAST_EC_X25519,
	password: new VirgilCrypto.Buffer('pa$$w0rd')
});
```

### generateKeyPairAsync(\[options\]) (Browsers only)

Same as [generateKeyPair](#generatekeypair_options) but returns a Promise that is resolved with generated
key pair or rejected with error.

#### Returns

* (Promise\<Object.\<{privateKey: Buffer, publicKey: Buffer}\>\>): Promise that will be resolved with the new key pair.

#### Examples


```javascript
VirgilCrypto.generateKeyPairAsync()
	.then(function (keyPair) {
		//{
        //   publicKey: ...,  // Buffer with public key
        //   privateKey: ...  // Buffer with private key
        //}
	});
```

## Encryption

### encrypt(data, recipientId | recipients | password, \[publicKey\])

#### Arguments

Encrypts the data with single recipient's public key, multiple recipients' public keys or password depending 
on the number and types of arguments passed.

* data (Buffer): Data to encrypt.
* recipientId|recipients|password: Either one of the following
	- recipientId (Buffer): Identifier of intended recipient.
	- recipients (Array.\<{recipientId: Buffer, publicKey: Buffer}\>): Array of recipient ids with corresponding 
	public keys to use for encryption. 
	- password (Buffer): Password to use for encryption.
* \[publicKey\] (Buffer): Public key to use for encryption. Used when encrypting for single recipient (i.e. when 
	second argument is recipientId)

#### Returns

* (Buffer): Encrypted data.

#### Examples

Using Password

```javascript
var plainText = new Buffer('data to be encrypted');
var password = new Buffer('pa$$w0rd');

var encryptedData = VirgilCrypto.encrypt(plainText, password);

console.log('Encrypted data: ' + encryptedData.toString('base64'));
```

Using Key

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair();
// using newly generated key pair and random recipient id here 
// as an example. In a real app the key would have been provided 
// externally (e.g. from web service, database, file, etc.)
var encryptedData = VirgilCrypto.encrypt(
					plainText, recipientId, keyPair.publicKey);

console.log('Encrypted data: ' + encryptedData.toString('base64'));
```

Using multiple keys

```javascript
var plainText = new Buffer('data to be encrypted');

var recipientId1 = new Buffer('<SOME_RECIPIENT_ID_1>');
var recipientId2 = new Buffer('<SOME_RECIPIENT_ID_2>');
var keyPair1 = VirgilCrypto.generateKeyPair();
var keyPair2 = VirgilCrypto.generateKeyPair();

// using newly generated key pairs and random recipient ids here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)

var recipientsList = [{ 
	recipientId: recipientId1, 
	publicKey: keyPair1.publicKey 
}, {
	recipientId: recipientId2,
	publicKey: keyPair2.publicKey
}];

var encryptedData = VirgilCrypto.encrypt(plaintText, recipientsList);

// encrypted data now can be decrypted by either keyPair1.privateKey 
// or keyPair2.privateKey

console.log('Encrypted data: ' + encryptedData.toString('base64'));
```


### encryptAsync(data, recipientId | recipients | password, \[publicKey\]) (Browsers only)

Same as [encrypt](#encrypt_data_recipientid_recipients_password_publickey) but returns a Promise 
that is resolved with encrypted data or rejected with error.

#### Returns

* (Promise.\<Buffer\>): Promise that will be resolved with encrypted data.

#### Examples

Using Password

```javascript
var plainText = new VirgilCrypto.Buffer('data to be encrypted');
var password = new VirgilCrypto.Buffer('pa$$w0rd');

VirgilCrypto.encryptAsync(plainText, password)
	.then(function (encryptedData) {
		console.log('Encrypted data: ' + encryptedData.toString('base64'));
	})
	.catch(function (err) {
		// handle error
		console.log(err);
	});
```

Using Key

```javascript
var plainText = new VirgilCrypto.Buffer('data to be encrypted');
var recipientId = new VirgilCrypto.Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair();
// using newly generated key pair and random recipient id here 
// as an example. In a real app the key would have been provided 
// externally (e.g. from web service, database, file, etc.)

VirgilCrypto.encryptAsync(plainText, recipientId, keyPair.publicKey)
	.then(function (encryptedData) {
		console.log('Encrypted data: ' + encryptedData.toString('base64'));
	})
	.catch(function (err) {
		// handle error
		console.log(err);
	});

console.log('Encrypted data: ' + encryptedData.toString('base64'));
```

Using multiple keys

```javascript
var plainText = new VirgilCrypto.Buffer('data to be encrypted');

var recipientId1 = new VirgilCrypto.Buffer('recipient1');
var recipientId2 = new VirgilCrypto.Buffer('recipient2');
var keyPair1 = VirgilCrypto.generateKeyPair();
var keyPair2 = VirgilCrypto.generateKeyPair();

// using newly generated key pairs and random recipient ids here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)

var recipientsList = [{ 
	recipientId: recipientId1, 
	publicKey: keyPair1.publicKey 
}, {
	recipientId: recipientId2,
	publicKey: keyPair2.publicKey
}];

VirgilCrypto.encryptAsync(plaintText, recipientsList)
	.then(function (encryptedData) {
		// encrypted data now can be decrypted by either keyPair1.privateKey 
		// or keyPair2.privateKey
		console.log('Encrypted data: ' + encryptedData.toString('base64'));
	})
	.catch(function (err) {
		// handle error
		console.log(err);
	});
```

## Decryption

### decrypt(encryptedData, recipientId | password, \[privateKey\], \[privateKeyPassword\])

Decrypts the data using password or private key depending on the number of arguments passed in.

#### Arguments

* encryptedData (Buffer): Data to decrypt.
* recipientId|password: Either one of the following
	- recipientId (Buffer): Recipient id used for encryption.
	- password (Buffer): Password to use for decryption.
* \[privateKey\] (Buffer): Private key to use for decryption.
* \[privateKeyPassword\] (Buffer): Password used to encrypt the private key.

#### Returns

* (Buffer): Decrypted data.

#### Examples

Using password:

```javascript
var password = new Buffer('pa$$w0rd');
var plainText = new Buffer('data to be encrypted');
var encryptedData = VirgilCrypto.encrypt(plainText, password);
var decryptedData = VirgilCrypto.decrypt(encryptedData, password);
console.log('Decrypted data: ' + decryptedData.toString('utf8'));
```

Using private key:

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair();
// using newly generated key pair and random recipient id here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)
var encryptedData = VirgilCrypto.encrypt(
					plainText, recipientId, keyPair.publicKey);
					
var decryptedData = VirgilCrypto.decrypt(
					encryptedData, recipientId, keyPair.privateKey);

console.log('Decrypted data: ' + decryptedData.toString('utf8'));
```

Using private key with password:

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');
var privateKeyPassword = new Buffer('pa$$w0rd');

var keyPair = VirgilCrypto.generateKeyPair({
	password: privateKeyPassword
});

// using newly generated key pair and random recipient id here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)

var encryptedData = VirgilCrypto.encrypt(
					plainText, recipientId, keyPair.publicKey);
					
var decryptedData = VirgilCrypto.decrypt(
					encryptedData, 
					recipientId, 
					keyPair.privateKey, 
					privateKeyPassword);

console.log('Decrypted data: ' + decryptedData.toString('utf8'));
```


### decryptAsync(encryptedData, recipientId | password, \[privateKey\], \[privateKeyPassword\]) (Browsers only)

Same as [decrypt](#decrypt_encrypteddata_recipientid_password_privatekey_privatekeypassword) but returns a 
Promise that is resolved with decrypted data or rejected with error.

#### Returns

* (Promise.\<Buffer\>): Decrypted data.

#### Examples

Using password:

```javascript
var password = new VirgilCrypto.Buffer('pa$$w0rd');
var plainText = new VirgilCrypto.Buffer('data to be encrypted');
VirgilCrypto.encryptAsync(plainText, password)
	.then(function (encryptedData) {
		return VirgilCrypto.decryptAsync(encryptedData, password);
	});
	.then(function (decryptedData) {
		console.log('Decrypted data: ' + decryptedData.toString('utf8'));	
	})
	.catch(function (err) {
	 	// handle error
	 	console.log(err);
	});
```

Using private key:

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair();
// using newly generated key pair and random recipient id here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)

VirgilCrypto.encryptAsync(plainText, recipientId, keyPair.publicKey)
	.then(function (encryptedData) {
		return VirgilCrypto.decryptAsync(
				encryptedData, recipientId, keyPair.privateKey);
	});
	.then(function (decryptedData) {
		console.log('Decrypted data: ' + decryptedData.toString('utf8'));	
	})
	.catch(function (err) {
		// handle error
		console.log(err);
	});

console.log('Decrypted data: ' + decryptedData.toString('utf8'));
```

Using private key with password:

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');
var privateKeyPassword = new Buffer('pa$$w0rd');

var keyPair = VirgilCrypto.generateKeyPair({
	password: privateKeyPassword
});

// using newly generated key pair and random recipient id here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)

VirgilCrypto.encryptAsync(plainText, recipientId, keyPair.publicKey)
	.then(function (encryptedData) {
		return VirgilCrypto.decryptAsync(
				encryptedData, 
				recipientId, 
				keyPair.privateKey, 
				privateKeyPassword);
	});
	.then(function (decryptedData) {
		console.log('Decrypted data: ' + decryptedData.toString('utf8'));	
	})
	.catch(function (err) {
		// handle error
		console.log(err);
	});
```

## Signatures

Cryptographic digital signatures use public key algorithms to provide authenticity and integrity assurances on the data. 
When you sign the data with a digital signature, someone else can verify the signature and can prove that the data 
originated from you and was not altered after you signed it.

### sign(data, privateKey, \[privateKeyPassword\])

Signs the data using private key and returns the signature.

#### Arguments

* data (Buffer): Data to sign
* privateKey (Buffer): Private key to use for signing.
* \[privateKeyPassword\]: Password used to encrypt the private key.

#### Returns

* (Buffer): Signature.

#### Examples

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair();

var encryptedData = VirgilCrypto.encrypt(plainText, recipientId, keyPair.publicKey);
var signature = VirgilCrypto.sign(encryptedData, keyPair.privateKey);

console.log(signature.toString('base64'));
```

Using encrypted private key

```javascript
var keyPassword = new Buffer('pa$$w0rd');
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair({ 
	password: keyPassword 
});

var encryptedData = VirgilCrypto.encrypt(plainText, recipientId, keyPair.publicKey);
var signature = VirgilCrypto.sign(encryptedData, keyPair.privateKey, keyPassword);

console.log(signature.toString('base64'));
```

### signAsync(data, privateKey, \[privateKeyPassword\]) (Browsers only)

Same as [sign](#sign_data_privatekey_privatekeypassword) but returns a Promise that will be 
resolved with the signature or rejected with error.

#### Returns

* (Promise.\<Buffer\>): Promise that will be resolved with the signature.

#### Examples

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair();

var encryptedData = VirgilCrypto.encrypt(plainText, recipientId, keyPair.publicKey);
VirgilCrypto.signAsync(encryptedData, keyPair.privateKey)
	.then(function (signature) {
		console.log(signature.toString('base64'));
	});
```

Using encrypted private key

```javascript
var keyPassword = new Buffer('pa$$w0rd');
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var keyPair = VirgilCrypto.generateKeyPair({ 
	password: keyPassword 
});

var encryptedData = VirgilCrypto.encrypt(plainText, recipientId, keyPair.publicKey);
VirgilCrypto.signAsync(encryptedData, keyPair.privateKey, keyPassword)
	.then(function (signature) {
		console.log(signature.toString('base64'));
	});
```

### verify(data, sign, publicKey)

Verifies the signature for the data and returns `true` if verification succeeded or `false` if it failed.

#### Arguments

* data (Buffer): Signed data.
* sign (Buffer): Digital signature.
* publicKey (Buffer): Public key of the party that signed the data.

#### Returns

* (boolean): `true` if verification succeeded or `false` if it failed.

#### Examples

```javascript
var isVerified = VirgilCrypto.verify(encryptedData, signature, keyPair.publicKey);
console.log('Is signature valid: ' + isVerified);
```

### verifyAsync(data, sign, publicKey) (Browsers only)

Same as [verify](#verify_data_sign_publickey) but returns a Promise that will be resolved with `true` if verification 
succeeded or `false` if it failed, or rejected with error.

#### Returns

* (Promise.\<boolean\>): Promise that will be resolved with `true` if verification succeeded or `false` if it failed.

#### Examples

```javascript
VirgilCrypto.verifyAsync(encryptedData, signature, keyPair.publicKey)
	.then(function (isVerified) {
		console.log('Is signature valid: ' + isVerified);
	});
```

## Authenticated Encryption

Form of encryption which simultaneously provides confidentiality, integrity, and authenticity assurances on the data.

### signThenEncrypt(data, privateKey, recipientId | recipients, [publicKey])

Combines encryption in a single step with message authentication. Signs the data using the private key and encrypts
the signed message using the public key (or public keys depending on the number of arguments passed).

#### Arguments

* data (Buffer): Data to sign and encrypt.
* privateKey (Buffer): Private key to use for signature generation.
* recipientId|recipients: Either one of the following
	- recipientId (Buffer): Identifier of intended recipient.
	- recipients (Array.\<{recipientId: Buffer, publicKey: Buffer}\>): Array of recipient ids with corresponding 
	public keys to use for encryption. 
* \[publicKey\] (Buffer): Public key to use for encryption. Used when encrypting for single recipient (i.e. when 
	second argument is recipientId)

#### Returns

* (Buffer): Encrypted signed data.

#### Examples

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var senderKeyPair = VirgilCrypto.generateKeyPair();
var recipientKeyPair = VirgilCrypto.generateKeyPair();

// using newly generated key pair and random recipient id here 
// as an example. In a real app the key would have been provided 
// externally (e.g. from web service, database, file, etc.)

var encryptedSignedData = VirgilCrypto.signThenEncrypt(
					plainText, 
					senderKeyPair, 
					recipientId, 
					recipientKeyPair.publicKey);

console.log('Encrypted data: ' + encryptedSignedData.toString('base64'));

```

### signThenEncryptAsync(data, privateKey, recipientId | recipients, [publicKey]) (Browsers only)

Same as [signThenEncrypt](#signThenEncrypt_data_privateKey_recipientId_recipients_publicKey) but returns a Promise
that will be resolved with encrypted data or rejected with error.

#### Returns

* (Promise.\<Buffer\>): Promise that will be resolved with encrypted signed data.

#### Examples

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var senderKeyPair = VirgilCrypto.generateKeyPair();
var recipientKeyPair = VirgilCrypto.generateKeyPair();

// using newly generated key pair and random recipient id here 
// as an example. In a real app the key would have been provided 
// externally (e.g. from web service, database, file, etc.)

VirgilCrypto.signThenEncryptAsync(
	plainText, senderKeyPair, recipientId, recipientKeyPair.publicKey)
.then(function (encryptedSignedData) {
	console.log('Encrypted data: ' + encryptedSignedData.toString('base64'));
})
.catch(function (err) {
	// handle error
	console.log(err);
});

```

### decryptThenVerify(cipherData, recipientId, privateKey, publicKey)

Combines decryption in a single step with integrity verification. Decrypts the data and verifies attached signature.
Returns decrypted data if verification succeeded or throws `VirgilCrypto.VirgilCryptoError` if it failed.

#### Arguments

* cipherData (Buffer): Encrypted signed data.
* recipientId (Buffer): Recipient id used for encryption.
* privateKey (Buffer): Private key to use for decryption.
* publicKey (Buffer): Sender's public key to use for signature verification.

#### Returns

* (Buffer): Decrypted data.

#### Examples

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var senderKeyPair = VirgilCrypto.generateKeyPair();
var recipientKeyPair = VirgilCrypto.generateKeyPair();

// using newly generated key pair and random recipient id here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)

var encryptedData = VirgilCrypto.signThenEncrypt(
					plainText, 
					senderKeyPair.privateKey, 
					recipientId, 
					recipientKeyPair.publicKey);
var decryptedData = null;

try {
	decryptedData = VirgilCrypto.decryptThenVerify(
    					encryptedData, 
    					recipientId, 
    					recipientKeyPair.privateKey, 
    					senderKeyPair.pubicKey);
} catch (err) {
	// Message integrity\authenticity verification failed
	console.log(err);
}

console.log('Decrypted data: ' + decryptedData.toString('utf8'));
```

### decryptThenVerifyAsync(cipherData, recipientId, privateKey, publicKey) (Browsers only)

Same as [decryptThenVerify](#decryptThenVerify_cipherData_recipientId_privateKey_publicKey) but returns a Promise
that will be resolved with decrypted data or rejected with `VirgilCrypto.VirgilCryptoError`.

#### Returns

* (Promise.\<Buffer\>): Decrypted data.

#### Examples

```javascript
var plainText = new Buffer('data to be encrypted');
var recipientId = new Buffer('<SOME_RECIPIENT_ID>');

var senderKeyPair = VirgilCrypto.generateKeyPair();
var recipientKeyPair = VirgilCrypto.generateKeyPair();

// using newly generated key pair and random recipient id here 
// as an example. In a real app the keys would have been provided 
// externally (e.g. from web service, database, file, etc.)

VirgilCrypto.signThenEncrypt(
	plainText, 
	senderKeyPair.privateKey, 
	recipientId, 
	recipientKeyPair.publicKey)
	.then(function (encryptedData) {
		return VirgilCrypto.decryptThenVerify(
			encryptedData, 
			recipientId, 
			recipientKeyPair.privateKey, 
			senderKeyPair.pubicKey);
	})
	.then(function (decryptedData) {
		console.log('Decrypted data: ' + decryptedData.toString('utf8'));
	})
	.catch(function (err) {
		// Message integrity\authenticity verification failed
        console.log(ex);
	});
```


## Hashing

### hash(data, \[algorithm = VirgilCrypto.HashAlgorithm.SHA256\])

Returns cryptographic hash of the message.

### Arguments

* data (Buffer): Data to compute the hash for.
* \[algorithm=VirgilCrypto.HashAlgorithm.SHA256\] (string): Name of hash algorithm to use (Default - SHA-256).

### Returns

* (Buffer): Computed hash.

### Supported hash algorithms

| Algorithm  |
|------------|
| SHA1       |
| SHA224     |
| SHA256     |
| SHA384     |
| SHA512     |

e.g. `VirgilCrypto.HashAlgorithm.SHA1` for SHA1 hash.


### obfuscate(value, salt, \[algorithm = VirgilCrypto.HashAlgorithm.SHA384\], \[iterations = 2048\])

Returns an obfuscated value derived with PBKDF using the given salt, hash algorithm and number of iterations.

#### Arguments

* value (Buffer): Value to obfuscate.
* salt (Buffer): Salt for PBKDF.
* \[algorithm=VirgilCrypto.HashAlgorithm.SHA384\] (string): Name of hash algorithm to use (Default - SHA-384).
* \[iterations\] (iterations): Number of iterations for PBKDF.

#### Returns

* (Buffer): Obfuscated value.


## Key pair utils

### changePrivateKeyPassword(privateKey, oldPassword, newPassword)

Changes the password used to encrypt the private key. Returns private key encrypted using new password.

#### Arguments

* privateKey (Buffer): Private key.
* oldPassword (Buffer): Old password.
* newPassword (Buffer): New password.

#### Returns

* (Buffer): Private key encrypted using new password.


### decryptPrivateKey(privateKey, privateKeyPassword)

Decrypts and returns the private key.

#### Arguments

* privateKey (Buffer): Private key to decrypt.
* privateKeyPassword (Buffer): Password used to encrypt the private key.

#### Returns

* (Buffer): Unencrypted private key.


### encryptPrivateKey(privateKey, privateKeyPassword)

Encrypts and returns the private key.

#### Arguments

* privateKey (Buffer): Private key to encrypt.
* privateKeyPassword (Buffer): Password to use for encryption. 

#### Returns

* (Buffer): Encrypted private key.


### VirgilCrypto.extractPrivateKey(privateKey, \[privateKeyPassword\])

Returns public key computed from private key.

#### Arguments

* privateKey (Buffer): Private key from which public key is computed.
* \[privateKeyPassword\] (Buffer): Password used for private key encryption if applicable.

#### Returns

* (Buffer): Public key.


### privateKeyToDER(privateKey, \[privateKeyPassword\])

Returns the private key in DER format.

#### Arguments

* privateKey (Buffer): Private key to convert to DER format.
* \[privateKeyPassword\] (Buffer): Password used for private key encryption if applicable.

#### Returns

* (Buffer): Private key in DER format.

### publicKeyToDER(publicKey)

Returns the public key in DER format.

#### Arguments

* publicKey (Buffer): Public key to convert to DER format.

#### Returns

* (Buffer): Public key in DER format.


## Resources

* [Crypto Library](https://github.com/VirgilSecurity/virgil/blob/master/javascript/crypto-library/readme.md)
* [SDK](https://github.com/VirgilSecurity/virgil/blob/master/javascript/keys-sdk/readme.md)

## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE) for details.

## Contacts
Email: <support@virgilsecurity.com>
