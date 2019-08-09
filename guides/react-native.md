# Virgil Security JavaScript Crypto Library - React Native
We created a [native module for React Native](https://github.com/VirgilSecurity/react-native-virgil-crypto).

This library's API is compatible with the [virgil-crypto for JavaScript](https://github.com/VirgilSecurity/virgil-crypto-javascript) and can be used in place of the latter in React Native projects. The main difference is that in JS library a class named `VirgilCrypto` is exported from the module that you need to create instances of, whereas this library exports an "instance" of that class ready to be used. Also, stream encryption is not available as there is no stream implementation in React Native. We're investigating the options to support file encryption though.

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
