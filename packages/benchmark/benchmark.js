const { Buffer: NodeBuffer } = require('buffer');
const { initCrypto, VirgilCrypto: V4Crypto } = require('virgil-crypto');
const { VirgilCrypto: V3Crypto } = require('virgil-crypto-3');

const data = NodeBuffer.from(
  'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
  'utf8',
);

const createSuite = (benchmark, log) => {
  const suite = new benchmark.Suite();
  suite.on('cycle', event => {
    log(`- ${String(event.target)}`);
  });
  suite.on('complete', function() {
    log(`\nFastest is ${this.filter('fastest').map('name')}`);
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
  log('### generateKeys');
  suite.add('v3', () => {
    v3Crypto.generateKeys();
  });
  suite.add('v4', () => {
    v4Crypto.generateKeys();
  });
  suite.run();
};

const generateKeysFromKeyMaterialBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyMaterial = v3Crypto.getRandomBytes(32);
  const suite = createSuite(benchmark, log);
  log('### generateKeysFromKeyMaterial');
  suite.add('v3', () => {
    v3Crypto.generateKeysFromKeyMaterial(keyMaterial);
  });
  suite.add('v4', () => {
    v4Crypto.generateKeysFromKeyMaterial(keyMaterial);
  });
  suite.run();
};

const importPrivateKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const privateKey = v3Crypto.exportPrivateKey(keyPair.v3.privateKey);
  const suite = createSuite(benchmark, log);
  log('### importPrivateKey');
  suite.add('v3', () => {
    v3Crypto.importPrivateKey(privateKey);
  });
  suite.add('v4', () => {
    v4Crypto.importPrivateKey(privateKey);
  });
  suite.run();
};

const exportPrivateKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  log('### exportPrivateKey');
  suite.add('v3', () => {
    v3Crypto.exportPrivateKey(keyPair.v3.privateKey);
  });
  suite.add('v4', () => {
    v4Crypto.exportPrivateKey(keyPair.v4.privateKey);
  });
  suite.run();
};

const importPublicKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const publicKey = v3Crypto.exportPublicKey(keyPair.v3.publicKey);
  const suite = createSuite(benchmark, log);
  log('### importPublicKey');
  suite.add('v3', () => {
    v3Crypto.importPublicKey(publicKey);
  });
  suite.add('v4', () => {
    v4Crypto.importPublicKey(publicKey);
  });
  suite.run();
};

const exportPublicKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  log('### exportPublicKey');
  suite.add('v3', () => {
    v3Crypto.exportPublicKey(keyPair.v3.publicKey);
  });
  suite.add('v4', () => {
    v4Crypto.exportPublicKey(keyPair.v4.publicKey);
  });
  suite.run();
};

const encryptBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  log('### encrypt');
  suite.add('v3', () => {
    v3Crypto.encrypt(data, keyPair.v3.publicKey);
  });
  suite.add('v4', () => {
    v4Crypto.encrypt(data, keyPair.v4.publicKey);
  });
  suite.run();
};

const decryptBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const encrypted = v3Crypto.encrypt(data, keyPair.v3.publicKey);
  const suite = createSuite(benchmark, log);
  log('### decrypt');
  suite.add('v3', () => {
    v3Crypto.decrypt(encrypted, keyPair.v3.privateKey);
  });
  suite.add('v4', () => {
    v4Crypto.decrypt(encrypted, keyPair.v4.privateKey);
  });
  suite.run();
};

const calculateHashBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const suite = createSuite(benchmark, log);
  log('### calculateHash');
  suite.add('v3', () => {
    v3Crypto.calculateHash(data);
  });
  suite.add('v4', () => {
    v4Crypto.calculateHash(data);
  });
  suite.run();
};

const extractPublicKeyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  log('### extractPublicKey');
  suite.add('v3', () => {
    v3Crypto.extractPublicKey(keyPair.v3.privateKey);
  });
  suite.add('v4', () => {
    v4Crypto.extractPublicKey(keyPair.v4.privateKey);
  });
  suite.run();
};

const calculateSignatureBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  log('### calculateSignature');
  suite.add('v3', () => {
    v3Crypto.calculateSignature(data, keyPair.v3.privateKey);
  });
  suite.add('v4', () => {
    v4Crypto.calculateSignature(data, keyPair.v4.privateKey);
  });
  suite.run();
};

const verifySignatureBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const signature = v3Crypto.calculateSignature(data, keyPair.v3.privateKey);
  const suite = createSuite(benchmark, log);
  log('### verifySignature');
  suite.add('v3', () => {
    v3Crypto.verifySignature(data, signature, keyPair.v3.publicKey);
  });
  suite.add('v4', () => {
    v4Crypto.verifySignature(data, signature, keyPair.v4.publicKey);
  });
  suite.run();
};

const signThenEncryptBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  log('### signThenEncrypt');
  suite.add('v3', () => {
    v3Crypto.signThenEncrypt(data, keyPair.v3.privateKey, keyPair.v3.publicKey);
  });
  suite.add('v4', () => {
    v4Crypto.signThenEncrypt(data, keyPair.v4.privateKey, keyPair.v4.publicKey);
  });
  suite.run();
};

const decryptThenVerifyBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const encrypted = v3Crypto.signThenEncrypt(data, keyPair.v3.privateKey, keyPair.v3.publicKey);
  const suite = createSuite(benchmark, log);
  log('### decryptThenVerify');
  suite.add('v3', () => {
    v3Crypto.decryptThenVerify(encrypted, keyPair.v3.privateKey, keyPair.v3.publicKey);
  });
  suite.add('v4', () => {
    v4Crypto.decryptThenVerify(encrypted, keyPair.v4.privateKey, keyPair.v4.publicKey);
  });
  suite.run();
};

const getRandomBytesBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const len = 64;
  const suite = createSuite(benchmark, log);
  log('### getRandomBytes');
  suite.add('v3', () => {
    v3Crypto.getRandomBytes(len);
  });
  suite.add('v4', () => {
    v4Crypto.getRandomBytes(len);
  });
  suite.run();
};

const signThenEncryptDetachedBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const suite = createSuite(benchmark, log);
  log('### signThenEncryptDetached');
  suite.add('v3', () => {
    v3Crypto.signThenEncryptDetached(data, keyPair.v3.privateKey, keyPair.v3.publicKey);
  });
  suite.add('v4', () => {
    v4Crypto.signThenEncryptDetached(data, keyPair.v4.privateKey, keyPair.v4.publicKey);
  });
  suite.run();
};

const decryptThenVerifyDetachedBenchmark = (benchmark, log, v3Crypto, v4Crypto) => {
  const keyPair = generateKeyPair(v3Crypto, v4Crypto);
  const { encryptedData, metadata } = v3Crypto.signThenEncryptDetached(
    data,
    keyPair.v3.privateKey,
    keyPair.v3.publicKey,
  );
  const suite = createSuite(benchmark, log);
  log('### decryptThenVerifyDetached');
  suite.add('v3', () => {
    v3Crypto.decryptThenVerifyDetached(
      encryptedData,
      metadata,
      keyPair.v3.privateKey,
      keyPair.v3.publicKey,
    );
  });
  suite.add('v4', () => {
    v4Crypto.decryptThenVerifyDetached(
      encryptedData,
      metadata,
      keyPair.v4.privateKey,
      keyPair.v4.publicKey,
    );
  });
  suite.run();
};

const groupEncryptBenchmark = (benchmark, log, _, v4Crypto) => {
  const keyPair = v4Crypto.generateKeys();
  const groupId = NodeBuffer.from('x'.repeat(10), 'utf8');
  const groupSession = v4Crypto.generateGroupSession(groupId);

  const suite = new benchmark.Suite();
  log('### Group Encryption (v4 only)');
  suite.on('cycle', event => {
    log(`- ${String(event.target)}`);
  });

  suite.add('encrypt', () => {
    groupSession.encrypt(data, keyPair.privateKey);
  });

  suite.run();
};

const groupDecryptBenchmark = (benchmark, log, _, v4Crypto) => {
  const keyPair = v4Crypto.generateKeys();
  const groupId = NodeBuffer.from('x'.repeat(10), 'utf8');
  const groupSession = v4Crypto.generateGroupSession(groupId);
  const encrypted = groupSession.encrypt(data, keyPair.privateKey);

  const suite = new benchmark.Suite();
  log('### Group Decryption (v4 only)');
  suite.on('cycle', event => {
    log(`- ${String(event.target)}`);
  });

  suite.add('decrypt', () => {
    groupSession.decrypt(encrypted, keyPair.publicKey);
  });

  suite.run();
};

const runBenchmark = async (benchmark, log) => {
  await initCrypto();

  const run = fn => {
    const v3Crypto = new V3Crypto();
    const v4Crypto = new V4Crypto();
    fn(benchmark, log, v3Crypto, v4Crypto);
    log('');
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
  run(groupEncryptBenchmark);
  run(groupDecryptBenchmark);
};

module.exports = runBenchmark;
