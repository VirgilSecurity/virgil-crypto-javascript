# Benchmarks

Results below were obtained on macOS Mojave with Intel(R) Core(TM) i7-7820HQ CPU @ 2.90GHz

## Node.js (Version: v10.15.3)

### generateKeys
- v3 x 153 ops/sec ±2.47% (76 runs sampled)
- v4 x 224 ops/sec ±2.99% (77 runs sampled)

Fastest is v4

### generateKeysFromKeyMaterial
- v3 x 157 ops/sec ±1.68% (78 runs sampled)
- v4 x 244 ops/sec ±1.73% (82 runs sampled)

Fastest is v4

### importPrivateKey
- v3 x 247 ops/sec ±1.40% (83 runs sampled)
- v4 x 10,187 ops/sec ±2.14% (87 runs sampled)

Fastest is v4

### exportPrivateKey
- v3 x 43,109,066 ops/sec ±8.58% (65 runs sampled)
- v4 x 11,302 ops/sec ±2.02% (88 runs sampled)

Fastest is v3

### importPublicKey
- v3 x 508 ops/sec ±0.85% (90 runs sampled)
- v4 x 138,722 ops/sec ±2.97% (83 runs sampled)

Fastest is v4

### exportPublicKey
- v3 x 106,722,197 ops/sec ±7.41% (68 runs sampled)
- v4 x 5,837,392 ops/sec ±2.79% (90 runs sampled)

Fastest is v3

### encrypt
- v3 x 250 ops/sec ±0.35% (89 runs sampled)
- v4 x 3,097 ops/sec ±0.76% (90 runs sampled)

Fastest is v4

### decrypt
- v3 x 236 ops/sec ±1.00% (84 runs sampled)
- v4 x 2,885 ops/sec ±1.91% (88 runs sampled)

Fastest is v4

### calculateHash
- v3 x 21,490 ops/sec ±2.45% (84 runs sampled)
- v4 x 183,644 ops/sec ±1.18% (91 runs sampled)

Fastest is v4

### extractPublicKey
- v3 x 498 ops/sec ±1.11% (88 runs sampled)
- v4 x 10,963 ops/sec ±1.65% (84 runs sampled)

Fastest is v4

### calculateSignature
- v3 x 477 ops/sec ±1.35% (87 runs sampled)
- v4 x 3,955 ops/sec ±0.74% (90 runs sampled)

Fastest is v4

### verifySignature
- v3 x 494 ops/sec ±0.57% (87 runs sampled)
- v4 x 5,025 ops/sec ±0.84% (90 runs sampled)

Fastest is v4

### signThenEncrypt
- v3 x 148 ops/sec ±2.18% (74 runs sampled)
- v4 x 1,669 ops/sec ±1.89% (89 runs sampled)

Fastest is v4

### decryptThenVerify
- v3 x 164 ops/sec ±1.58% (82 runs sampled)
- v4 x 1,833 ops/sec ±2.50% (86 runs sampled)

Fastest is v4

### getRandomBytes
- v3 x 482 ops/sec ±2.17% (85 runs sampled)
- v4 x 290,611 ops/sec ±3.66% (81 runs sampled)

Fastest is v4

### signThenEncryptDetached
- v3 x 165 ops/sec ±0.56% (82 runs sampled)
- v4 x 1,734 ops/sec ±0.69% (91 runs sampled)

Fastest is v4

### decryptThenVerifyDetached
- v3 x 157 ops/sec ±1.00% (78 runs sampled)
- v4 x 1,843 ops/sec ±1.44% (86 runs sampled)

Fastest is v4

### Group Encryption (v4 only)
- encrypt x 3,173 ops/sec ±1.88% (84 runs sampled)

### Group Decryption (v4 only)
- decrypt x 4,496 ops/sec ±0.51% (93 runs sampled)

## Browser (chrome/78.0.3882)

### generateKeys
- v3 x 54.45 ops/sec ±2.55% (47 runs sampled)
- v4 x 265 ops/sec ±0.44% (62 runs sampled)

Fastest is v4

### generateKeysFromKeyMaterial
- v3 x 70.79 ops/sec ±0.54% (53 runs sampled)
- v4 x 258 ops/sec ±1.00% (60 runs sampled)

Fastest is v4

### importPrivateKey
- v3 x 94.46 ops/sec ±1.17% (55 runs sampled)
- v4 x 13,254 ops/sec ±1.88% (60 runs sampled)

Fastest is v4

### exportPrivateKey
- v3 x 73,357,171 ops/sec ±0.54% (64 runs sampled)
- v4 x 13,616 ops/sec ±0.86% (63 runs sampled)

Fastest is v3

### importPublicKey
- v3 x 231 ops/sec ±0.81% (60 runs sampled)
- v4 x 181,675 ops/sec ±1.02% (62 runs sampled)

Fastest is v4

### exportPublicKey
- v3 x 815,835,828 ops/sec ±0.72% (65 runs sampled)
- v4 x 1,324,772 ops/sec ±0.45% (66 runs sampled)

Fastest is v3

### encrypt
- v3 x 76.34 ops/sec ±0.78% (57 runs sampled)
- v4 x 3,239 ops/sec ±1.23% (21 runs sampled)

Fastest is v4

### decrypt
- v3 x 77.17 ops/sec ±1.61% (53 runs sampled)
- v4 x 3,674 ops/sec ±0.46% (64 runs sampled)

Fastest is v4

### calculateHash
- v3 x 4,373 ops/sec ±0.96% (26 runs sampled)
- v4 x 159,126 ops/sec ±1.87% (59 runs sampled)

Fastest is v4

### extractPublicKey
- v3 x 189 ops/sec ±2.58% (60 runs sampled)
- v4 x 14,536 ops/sec ±0.46% (65 runs sampled)

Fastest is v4

### calculateSignature
- v3 x 142 ops/sec ±0.85% (56 runs sampled)
- v4 x 4,216 ops/sec ±1.29% (61 runs sampled)

Fastest is v4

### verifySignature
- v3 x 116 ops/sec ±1.86% (58 runs sampled)
- v4 x 6,167 ops/sec ±0.87% (35 runs sampled)

Fastest is v4

### signThenEncrypt
- v3 x 48.47 ops/sec ±0.74% (51 runs sampled)
- v4 x 1,835 ops/sec ±2.11% (14 runs sampled)

Fastest is v4

### decryptThenVerify
- v3 x 40.92 ops/sec ±1.59% (44 runs sampled)
- v4 x 2,204 ops/sec ±1.31% (64 runs sampled)

Fastest is v4

### getRandomBytes
- v3 x 247 ops/sec ±0.99% (61 runs sampled)
- v4 x 290,023 ops/sec ±1.52% (61 runs sampled)

Fastest is v4

### signThenEncryptDetached
- v3 x 43.18 ops/sec ±2.82% (46 runs sampled)
- v4 x 1,866 ops/sec ±2.37% (58 runs sampled)

Fastest is v4

### decryptThenVerifyDetached
- v3 x 47.78 ops/sec ±2.14% (51 runs sampled)
- v4 x 2,202 ops/sec ±0.85% (63 runs sampled)

Fastest is v4

### Group Encryption (v4 only)
- encrypt x 4,006 ops/sec ±1.47% (25 runs sampled)

### Group Decryption (v4 only)
- decrypt x 4,705 ops/sec ±4.67% (28 runs sampled)
