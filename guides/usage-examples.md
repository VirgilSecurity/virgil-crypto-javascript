# Virgil Security JavaScript Crypto Library - Usage Examples

## Generate a key pair
Generate a Private Key with the default algorithm (ED25519):
```js
import { initCrypto, VirgilCrypto } from 'virgil-crypto';
// You may replace this import with an import that suits your environment

initCrypto().then(() => {
  const virgilCrypto = new VirgilCrypto();
  const keyPair = virgilCrypto.generateKeys();
});
```

## Generate and verify a signature
Generate signature and sign data with a private key:
```js
import { initCrypto, VirgilCrypto } from 'virgil-crypto';
// You may replace this import with an import that suits your environment

initCrypto().then(() => {
  const virgilCrypto = new VirgilCrypto();
  const signingKeypair = virgilCrypto.generateKeys();

  // prepare a message
  const messageToSign = 'Hello, Bob!';

  // generate a signature
  const signature = virgilCrypto.calculateSignature(
    { value: messageToSign, encoding: 'utf8' },
    signingKeypair.privateKey
  );
  // signature is a NodeJS Buffer (or polyfill if in the browser)
  console.log(signature.toString('base64'));
});
```

Verify a signature with a public key:
```js
// verify a signature
const verified = virgilCrypto.verifySignature(
  { value: messageToSign, encoding: 'utf8' },
  signature,
  signingKeypair.publicKey
);
```

## Encrypt and decrypt data
Encrypt Data on a Public Key:
```js
import { initCrypto, VirgilCrypto } from 'virgil-crypto';
// You may replace this import with an import that suits your environment

initCrypto().then(() => {
  const virgilCrypto = new VirgilCrypto();
  const encryptionKeypair = virgilCrypto.generateKeys();

  // prepare a message
  const messageToEncrypt = 'Hello, Bob!';

  // generate a signature
  const encryptedData = virgilCrypto.encrypt(
    { value: messageToEncrypt, encoding: 'utf8' },
    encryptionKeypair.publicKey
  );
  // encryptedData is a NodeJS Buffer (or polyfill if in the browser)
  console.log(encryptedData.toString('base64'));
});
```

Decrypt the encrypted data with a Private Key:
```js
// decrypt the encrypted data using a private key
const decryptedData = virgilCrypto.decrypt(encryptedData, encryptionKeypair.privateKey);

// convert Buffer to string
const decryptedMessage = decryptedData.toString('utf8');
```

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
