const { Buffer: NodeBuffer } = require('buffer');
const { initCrypto, VirgilCrypto: V4Crypto } = require('virgil-crypto');
const { VirgilCrypto: V3Crypto } = require('virgil-crypto-3');

const createSuite = (benchmark, log) => {
  const suite = new benchmark.Suite();
  suite.on('cycle', event => {
    log(String(event.target));
  });
  suite.on('complete', function() {
    log(`Fastest is ${this.filter('fastest').map('name')}\n`);
  });
  return suite;
};

const generateKeyPair = (v3Crypto, v4Crypto) => {
  const { privateKey: v3PrivateKey, publicKey: v3PublicKey } = v3Crypto.generateKeys();
  const exportedPrivateKey = v3Crypto.exportPrivateKey(v3PrivateKey);
  const exportedPublicKey = v3Crypto.exportPublicKey(v3PublicKey);
  const v4PrivateKey = v4Crypto.importPrivateKey(exportedPrivateKey);
  const v4PublicKey = v4Crypto.importPublicKey(exportedPublicKey);
  return {
    v3: {
      privateKey: v3PrivateKey,
      publicKey: v3PublicKey,
    },
    v4: {
      privateKey: v4PrivateKey,
      publicKey: v4PublicKey,
    },
  };
};

const generateKeysBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const suite = createSuite(benchmark, log);
  suite.add('v3 - generateKeys', () => {
    v3Crypto.generateKeys();
  });
  suite.add('v4 - generateKeys', () => {
    v4Crypto.generateKeys();
  });
  suite.run();
};

const generateKeysFromKeyMaterialBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyMaterial = v3Crypto.getRandomBytes(32);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - generateKeysFromKeyMaterial', () => {
    v3Crypto.generateKeysFromKeyMaterial(keyMaterial);
  });
  suite.add('v4 - generateKeysFromKeyMaterial', () => {
    v4Crypto.generateKeysFromKeyMaterial(keyMaterial);
  });
  suite.run();
};

const importPrivateKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const privateKey = v3Crypto.exportPrivateKey(keyPair.v3.privateKey);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - importPrivateKey', () => {
    v3Crypto.importPrivateKey(privateKey);
  });
  suite.add('v4 - importPrivateKey', () => {
    v4Crypto.importPrivateKey(privateKey);
  });
  suite.run();
};

const exportPrivateKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - exportPrivateKey', () => {
    v3Crypto.exportPrivateKey(keyPair.v3.privateKey);
  });
  suite.add('v4 - exportPrivateKey', () => {
    v4Crypto.exportPrivateKey(keyPair.v4.privateKey);
  });
  suite.run();
};

const importPublicKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const publicKey = v3Crypto.exportPublicKey(keyPair.v3.publicKey);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - importPublicKey', () => {
    v3Crypto.importPublicKey(publicKey);
  });
  suite.add('v4 - importPublicKey', () => {
    v4Crypto.importPublicKey(publicKey);
  });
  suite.run();
};

const exportPublicKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - exportPublicKey', () => {
    v3Crypto.exportPublicKey(keyPair.v3.publicKey);
  });
  suite.add('v4 - exportPublicKey', () => {
    v4Crypto.exportPublicKey(keyPair.v4.publicKey);
  });
  suite.run();
};

const encryptBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - encrypt', () => {
    v3Crypto.encrypt(data, keyPair.v3.publicKey);
  });
  suite.add('v4 - encrypt', () => {
    v4Crypto.encrypt(data, keyPair.v4.publicKey);
  });
  suite.run();
};

const decryptBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const encrypted = v3Crypto.encrypt(data, keyPair.v3.publicKey);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - decrypt', () => {
    v3Crypto.decrypt(encrypted, keyPair.v3.privateKey);
  });
  suite.add('v4 - decrypt', () => {
    v4Crypto.decrypt(encrypted, keyPair.v4.privateKey);
  });
  suite.run();
};

const calculateHashBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const suite = createSuite(benchmark, log);
  suite.add('v3 - calculateHash', () => {
    v3Crypto.calculateHash(data);
  });
  suite.add('v4 - calculateHash', () => {
    v4Crypto.calculateHash(data);
  });
  suite.run();
};

const extractPublicKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - extractPublicKey', () => {
    v3Crypto.extractPublicKey(keyPair.v3.privateKey);
  });
  suite.add('v4 - extractPublicKey', () => {
    v4Crypto.extractPublicKey(keyPair.v4.privateKey);
  });
  suite.run();
};

const calculateSignatureBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - calculateSignature', () => {
    v3Crypto.calculateSignature(data, keyPair.v3.privateKey);
  });
  suite.add('v4 - calculateSignature', () => {
    v4Crypto.calculateSignature(data, keyPair.v4.privateKey);
  });
  suite.run();
};

const verifySignatureBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const signature = v3Crypto.calculateSignature(data, keyPair.v3.privateKey);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - verifySignature', () => {
    v3Crypto.verifySignature(data, signature, keyPair.v3.publicKey);
  });
  suite.add('v4 - verifySignature', () => {
    v4Crypto.verifySignature(data, signature, keyPair.v4.publicKey);
  });
  suite.run();
};

const signThenEncryptBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - signThenEncrypt', () => {
    v3Crypto.signThenEncrypt(data, keyPair.v3.privateKey, keyPair.v3.publicKey);
  });
  suite.add('v4 - signThenEncrypt', () => {
    v4Crypto.signThenEncrypt(data, keyPair.v4.privateKey, keyPair.v4.publicKey);
  });
  suite.run();
};

const decryptThenVerifyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const encrypted = v3Crypto.signThenEncrypt(data, keyPair.v3.privateKey, keyPair.v3.publicKey);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - decryptThenVerify', () => {
    v3Crypto.decryptThenVerify(encrypted, keyPair.v3.privateKey, keyPair.v3.publicKey);
  });
  suite.add('v4 - decryptThenVerify', () => {
    v4Crypto.decryptThenVerify(encrypted, keyPair.v4.privateKey, keyPair.v4.publicKey);
  });
  suite.run();
};

const getRandomBytesBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const len = 64;
  const suite = createSuite(benchmark, log);
  suite.add('v3 - getRandomBytes', () => {
    v3Crypto.getRandomBytes(len);
  });
  suite.add('v4 - getRandomBytes', () => {
    v4Crypto.getRandomBytes(len);
  });
  suite.run();
};

const signThenEncryptDetachedBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  suite.add('v3 - signThenEncryptDetached', () => {
    v3Crypto.signThenEncryptDetached(data, keyPair.v3.privateKey, keyPair.v3.publicKey);
  });
  suite.add('v4 - signThenEncryptDetached', () => {
    v4Crypto.signThenEncryptDetached(data, keyPair.v4.privateKey, keyPair.v4.publicKey);
  });
  suite.run();
};

const decryptThenVerifyDetachedBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const data = NodeBuffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    'utf8',
  );
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const { encryptedData, metadata } = v3Crypto.signThenEncryptDetached(
    data,
    keyPair.v3.privateKey,
    keyPair.v3.publicKey,
  );
  const suite = createSuite(benchmark, log);
  suite.add('v3 - decryptThenVerifyDetached', () => {
    v3Crypto.decryptThenVerifyDetached(
      encryptedData,
      metadata,
      keyPair.v3.privateKey,
      keyPair.v3.publicKey,
    );
  });
  suite.add('v4 - decryptThenVerifyDetached', () => {
    v4Crypto.decryptThenVerifyDetached(
      encryptedData,
      metadata,
      keyPair.v4.privateKey,
      keyPair.v4.publicKey,
    );
  });
  suite.run();
};

const runBenchmark = (benchmark, log) => {
  initCrypto().then(() => {
    const run = fn => {
      const v3Crypto = new V3Crypto();
      const v4Crypto = new V4Crypto();
      return fn(benchmark, log, v3Crypto, v4Crypto);
    };

    run(generateKeysBenchmark);
    run(generateKeysFromKeyMaterialBenchmark);
    run(importPrivateKeyBenchmark);
    run(exportPrivateKeyBenchmark);
    run(importPublicKeyBenchmark);
    run(exportPublicKeyBenchmark);
    run(encryptBenchmark);
    run(decryptBenchmark);
    run(calculateHashBenchmark);
    run(extractPublicKeyBenchmark);
    run(calculateSignatureBenchmark);
    run(verifySignatureBenchmark);
    run(signThenEncryptBenchmark);
    run(decryptThenVerifyBenchmark);
    run(getRandomBytesBenchmark);
    run(signThenEncryptDetachedBenchmark);
    run(decryptThenVerifyDetachedBenchmark);
  });
};

module.exports = runBenchmark;
