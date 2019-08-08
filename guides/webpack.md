# Virgil Security JavaScript Crypto Library - Webpack
Select approach you have decided to use:
- [WebAssembly](#webassembly)
- [asm.js](#asmjs)

## WebAssembly
First, you need to install [file-loader](https://github.com/webpack-contrib/file-loader) if you haven't used it yet:
```sh
npm install file-loader --save-dev
```

Second, you need to add a [rule](https://webpack.js.org/configuration/module/#rule) to copy WebAssembly file:
```js
{
  test: /\.wasm$/,
  type: 'javascript/auto',
  loader: 'file-loader',
  options: {
    name: '[name].[ext]'
  }
}
```

Third, you need to [disable mocking of Node.js modules and globals](https://webpack.js.org/configuration/node) in your Webpack config:
```js
node: false
```

Last, you need to import the library:
```js
import { initCrypto } 'virgil-crypto';
```

Here is [complete working demo](https://github.com/VirgilSecurity/virgil-crypto-javascript/tree/master/packages/webpack-demo) of this approach.

## asm.js
First, you need to [disable mocking of Node.js modules and globals](https://webpack.js.org/configuration/node) in your Webpack config:
```js
node: false
```

And then simply import the library:
```js
import { initCrypto } from 'virgil-crypto/dist/browser.asmjs.es';
```

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
