# Virgil Security JavaScript Crypto Library - UMD module
First, you need to add a `<script>` tag depending on approach you have decided to follow:
- WebAssembly. This is our recommended approach. [List of supported browsers](https://caniuse.com/#feat=wasm).
  ```html
  <script type="text/javascript" src="https://unpkg.com/virgil-crypto/dist/browser.umd.js"></script>
  ```
- asm.js. Use it only in case you need to support old web browsers.
  ```html
  <script type="text/javascript" src="https://unpkg.com/virgil-crypto/dist/browser.asmjs.umd.js"></script>
  ```

And then simply use the library:
```js
// Use the global variable `VirgilCrypto` as a namespace object,
// containing all of module exports as properties
const { initCrypto } = VirgilCrypto;
```

Also make sure to get familiar with [usage examples](usage-examples.md) of the library.

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
