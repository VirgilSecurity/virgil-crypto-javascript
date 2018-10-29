## Example of file encryption in the browser

Uses the `VirgilCrypto#createStreamCipher` and `VirgilCrypto#createStreamDecipher` to asynchronously encrypt and decrypt files uploaded to the server.

### Setup

Move to the `examples/file-upload` folder, install dependencies and start the server

> The `--no-package-lock` flag is needed because the virgil-crypto module is installed from file system and it may fail to install from package-lock.json

```sh
cd examples/file-upload
npm install --no-package-lock
npm start
```

Open http://localhost:3004 in a browser and select an image to upload. Open the browser console to see the progess messages. 
Uploaded images will be saved into `example/file-upload/uploads` folder. Example uses images, but it can be any type of file.
The size of files that can be uploaded depends on the `Blob` size limit in your browser.
