> This README is for virgil-crypto v4. Check the [v3 branch](https://github.com/VirgilSecurity/virgil-crypto-javascript/tree/v3) for virgil-crypto v3 docs.

# Virgil Security JavaScript Crypto Library
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript.svg)](https://travis-ci.org/VirgilSecurity/virgil-crypto-javascript)
[![npm](https://img.shields.io/npm/v/virgil-crypto.svg)](https://www.npmjs.com/package/virgil-crypto)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

### [Introduction](#introduction) | [Library purposes](#library-purposes) | [Getting started](#getting-started) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction
VirgilCrypto is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an
open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto-c) that allows you to
perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library
is written in C++ and is suitable for mobile and server platforms.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be
encrypted (and passwords will be eliminated). In this world, the days of developers having to raise millions of
dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end. Now
developers can instead focus on building features that give them a competitive market advantage while end-users can
enjoy the privacy and security they increasingly demand.

## Library purposes
- Asymmetric Key Generation
- Encryption/Decryption of data
- Generation/Verification of digital signatures

## Getting started
First, you need to install the package from npm:
```sh
npm install virgil-crypto
```
> If you are not using npm, follow our [UMD guide](https://github.com/VirgilSecurity/virgil-crypto-javascript/tree/master/guides/umd.md) to get started.

Second, you need to decide which approach to use in your application. We provide 2 options here:
- WebAssembly. This is our recommended approach. [List of supported browsers](https://caniuse.com/#feat=wasm).
- asm.js. Use it only in case you need to support old web browsers.

Third, you will need to setup you development environment (skip this step if you are using Node.js):
- [Webpack](https://github.com/VirgilSecurity/virgil-crypto-javascript/tree/master/guides/webpack.md)
- [Create React App](https://github.com/VirgilSecurity/virgil-crypto-javascript/tree/master/guides/create-react-app.md)
- [React Native](https://github.com/VirgilSecurity/virgil-crypto-javascript/tree/master/guides/react-native.md)
> Not found your environment? Create an issue on GitHub and we will try our best to help you. Make sure to describe your environment as much as possible.

Last, you need to get familiar with [usage examples](guides/usage-examples.md) of the library.

## Docs
- [API Reference](http://virgilsecurity.github.io/virgil-crypto-javascript/)
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto-c)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License
This library is released under the [3-clause BSD License](https://github.com/VirgilSecurity/virgil-crypto-javascript/tree/master/LICENSE).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
