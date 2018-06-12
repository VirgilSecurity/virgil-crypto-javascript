# Virgil Security JavaScript Crypto Library 
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript.svg)](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript) 
[![npm](https://img.shields.io/npm/v/virgil-crypto.svg)](https://www.npmjs.com/package/virgil-crypto)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

### [Introduction](#introduction) | [Library purposes](#library-purposes) | [Usage examples](#usage-examples) | [Installation](#installation) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction
VirgilCrypto is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated). In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end. Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

## Library purposes
* Asymmetric Key Generation
* Encryption/Decryption of data
* Generation/Verification of digital signatures

## Usage examples

#### Generate a key pair

Generate a Private Key with the default algorithm (EC_X25519):

```javascript
import { createVirgilCrypto } from 'virgil-crypto';

const virgilCrypto = createVirgilCrypto();
const keyPair = virgilCrypto.generateKeys();
```

#### Generate and verify a signature

Generate signature and sign data with a private key:

```javascript
import { createVirgilCrypto } from 'virgil-crypto';

const virgilCrypto = createVirgilCrypto();
const signingKeypair = virgilCrypto.generateKeys();

// prepare a message
const messageToSign = 'Hello, Bob!';

// generate a signature
const signature = virgilCrypto.calculateSignature(messageToSign, signingKeypair.privateKey);
// signature is a NodeJS Buffer (or polyfill if in the browser)
console.log(signature.toString('base64'));
```

Verify a signature with a public key:

```javascript
// verify a signature
const verified = virgilCrypto.verifySignature(messageToSign, signature, signingKeypair.publicKey);
```

#### Encrypt and decrypt data

Encrypt Data on a Public Key:

```javascript
import { createVirgilCrypto } from 'virgil-crypto';

const virgilCrypto = createVirgilCrypto();
const encryptionKeypair = virgilCrypto.generateKeys();

// prepare a message
const messageToEncrypt = 'Hello, Bob!';

// encrypt the message
const encryptedData = virgilCrypto.encrypt(messageToEncrypt, encryptionKeypair.publicKey);
// encryptedData is a NodeJS Buffer (or polyfill if in the browser)
console.log(encryptedData.toString('base64'));
```

Decrypt the encrypted data with a Private Key:

```javascript
// decrypt the encrypted data using a private key
const decryptedData = virgilCrypto.decrypt(encryptedData, encryptionKeypair.privateKey);

// convert Buffer to string
const decryptedMessage = decryptedData.toString('utf8');
```

Need more examples? Visit our [developer documentation](https://developer.virgilsecurity.com/docs/how-to#cryptography).
  
## Installation

### NPM

This is a pre-release version, so for now you will need to specify the `@next` tag when installing

```sh
npm install virgil-crypto@next
```

> **Important!** You will need Node.js version >= 4.5.0 < 5 or >= 6 to use virgil-crypto.
If you have a different version, consider upgrading, or use [nvm](https://github.com/creationix/nvm) 
(or a similar tool) to install Node.js of supported version alongside your current installation.  
If you only intend to use virgil-crypto in a browser environment, you can ignore this warning.

### CDN

```html
<script src="https://unpkg.com/virgil-crypto@next/dist/virgil-crypto.browser.umd.min.js"></script>
<script>
	// here you can use the global variable `VirgilCrypto` as a namespace object,
	// containing all of module exports as properties
	
	var virgilCrypto = VirgilCrypto.createVirgilCrypto();
	var keyPair = virgilCrypto.generateKeys();
	console.log(keyPair);
	
	// note that you cannot declare a variable named `crypto` in
	// global scope (i.e. outside of any function) in browsers that 
	// implement Web Crypto API
</script>
```

## Pythia

Support for [Pythia](https://virgilsecurity.com/wp-content/uploads/2018/05/Pythia-Service-by-Virgil-Security-Whitepaper-May-2018.pdf) algorithms is considered experimental.

### Usage

In Node.js:

```js
const { createVirgilPythia } = require('virgil-crypto/dist/virgil-crypto-pythia.cjs');

const virgilPythia = createVirgilPythia();

const tweak = Buffer.from('my_tweak');
const { blindingSecret, blindedPassword } = virgilPythia.blind('pa$$w0rd');

const transformationKeyPair = virgilPythia.computeTransformationKeyPair({
	transformationKeyId: Buffer.from('my_transformation_key_id'),
	pythiaSecret: Buffer.from('my_pythia_secret'),
	pythiaScopeSecret: Buffer.from('my_pythia_scope_secret')
});

const { transformedPassword, transformedTweak } = virgilPythia.transform({
	blindedPassword,
	tweak,
	transformationPrivateKey: transformationKeyPair.privateKey
});

const { proofValueC, proofValueU } = virgilPythia.prove({
	transformedPassword,
	blindedPassword,
	transformedTweak,
	transformationKeyPair
});

const verified = virgilPythia.verify({
	transformedPassword,
	blindedPassword,
	tweak,
	transformationPublicKey: transformationKeyPair.publicKey,
	proofValueC,
	proofValueU
});

console.log(verified);

const deblinded = virgilPythia.deblind({
	transformedPassword,
	blindingSecret
});

console.log(deblinded);
```

For browser example, see [examples/virgil-pythia.html](./examples/virgil-pythia.html).

## Docs
- [API Reference](http://virgilsecurity.github.io/virgil-crypto-javascript/)
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License
This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).
