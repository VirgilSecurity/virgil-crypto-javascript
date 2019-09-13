# Benchmarks
## Node.js
### generateKeys
- v3 x 141 ops/sec ±1.82% (78 runs sampled)
- v4 x 225 ops/sec ±4.19% (75 runs sampled)

Fastest is v4

### generateKeysFromKeyMaterial
- v3 x 133 ops/sec ±4.00% (73 runs sampled)
- v4 x 192 ops/sec ±5.89% (65 runs sampled)

Fastest is v4

### importPrivateKey
- v3 x 210 ops/sec ±1.79% (80 runs sampled)
- v4 x 8,021 ops/sec ±2.24% (87 runs sampled)

Fastest is v4

### exportPrivateKey
- v3 x 27,873,132 ops/sec ±2.04% (87 runs sampled)
- v4 x 8,393 ops/sec ±1.25% (87 runs sampled)

Fastest is v3

### importPublicKey
- v3 x 454 ops/sec ±0.95% (89 runs sampled)
- v4 x 73,855 ops/sec ±0.88% (96 runs sampled)

Fastest is v4

### exportPublicKey
- v3 x 87,345,231 ops/sec ±1.38% (85 runs sampled)
- v4 x 4,171,978 ops/sec ±0.32% (93 runs sampled)

Fastest is v3

### encrypt
- v3 x 222 ops/sec ±0.69% (84 runs sampled)
- v4 x 2,308 ops/sec ±1.53% (88 runs sampled)

Fastest is v4

### decrypt
- v3 x 224 ops/sec ±0.38% (85 runs sampled)
- v4 x 2,294 ops/sec ±1.04% (91 runs sampled)

Fastest is v4

### calculateHash
- v3 x 18,918 ops/sec ±3.31% (88 runs sampled)
- v4 x 28,221 ops/sec ±0.63% (95 runs sampled)

Fastest is v4

### extractPublicKey
- v3 x 460 ops/sec ±0.57% (90 runs sampled)
- v4 x 9,094 ops/sec ±0.48% (95 runs sampled)

Fastest is v4

### calculateSignature
- v3 x 447 ops/sec ±1.38% (92 runs sampled)
- v4 x 2,723 ops/sec ±4.99% (90 runs sampled)

Fastest is v4

### verifySignature
- v3 x 450 ops/sec ±0.21% (92 runs sampled)
- v4 x 3,851 ops/sec ±0.47% (92 runs sampled)

Fastest is v4

### signThenEncrypt
- v3 x 148 ops/sec ±0.56% (81 runs sampled)
- v4 x 1,240 ops/sec ±1.88% (92 runs sampled)

Fastest is v4

### decryptThenVerify
- v3 x 147 ops/sec ±1.37% (81 runs sampled)
- v4 x 1,378 ops/sec ±1.00% (92 runs sampled)

Fastest is v4

### getRandomBytes
- v3 x 474 ops/sec ±0.10% (92 runs sampled)
- v4 x 251,073 ops/sec ±2.00% (86 runs sampled)

Fastest is v4

### signThenEncryptDetached
- v3 x 146 ops/sec ±1.59% (81 runs sampled)
- v4 x 1,240 ops/sec ±0.81% (92 runs sampled)

Fastest is v4

### decryptThenVerifyDetached
- v3 x 148 ops/sec ±0.46% (81 runs sampled)
- v4 x 1,406 ops/sec ±0.38% (93 runs sampled)

Fastest is v4

## Browser