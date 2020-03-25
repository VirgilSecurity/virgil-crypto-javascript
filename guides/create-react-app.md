# Virgil Security JavaScript Crypto Library - Create React App
You need an ability to tweak [create-react-app](https://github.com/facebook/create-react-app) configs. You have 2 options here:
- Override options using [react-app-rewired](https://github.com/timarney/react-app-rewired) or its alternatives.
- [Eject](https://facebook.github.io/create-react-app/docs/available-scripts#npm-run-eject). Please note that this is a one-way operation.

## react-app-rewired
Add the following to your `config-overrides.js`:
```js
const path = require('path');
module.exports = (config, env) => {
  // Use file-loader to copy WebAssembly files
  // https://github.com/facebook/create-react-app/blob/master/packages/react-scripts/config/webpack.config.js#L378
  config.module.rules[2].oneOf.unshift({
    test: /\.wasm$/,
    type: 'javascript/auto',
    loader: 'file-loader',
  });
  return config;
};
```

## Eject
Follow our [Webpack guide](webpack.md).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
