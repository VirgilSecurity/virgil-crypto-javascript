# Benchmarks
## Node.js
### generateKeys
- v3 x 138 ops/sec ±1.15% (76 runs sampled)
- v4 x 247 ops/sec ±2.56% (81 runs sampled)

Fastest is v4

### generateKeysFromKeyMaterial
- v3 x 151 ops/sec ±0.46% (83 runs sampled)
- v4 x 251 ops/sec ±2.13% (83 runs sampled)

Fastest is v4

### importPrivateKey
- v3 x 222 ops/sec ±0.97% (84 runs sampled)
- v4 x 8,197 ops/sec ±0.89% (91 runs sampled)

Fastest is v4

### exportPrivateKey
- v3 x 27,635,258 ops/sec ±1.02% (87 runs sampled)
- v4 x 8,522 ops/sec ±1.14% (86 runs sampled)

Fastest is v3

### importPublicKey
- v3 x 457 ops/sec ±0.31% (89 runs sampled)
- v4 x 72,480 ops/sec ±0.81% (91 runs sampled)

Fastest is v4

### exportPublicKey
- v3 x 87,024,710 ops/sec ±0.51% (94 runs sampled)
- v4 x 3,577,575 ops/sec ±1.36% (88 runs sampled)

Fastest is v3

### encrypt
- v3 x 203 ops/sec ±0.81% (78 runs sampled)
- v4 x 2,151 ops/sec ±1.95% (83 runs sampled)

Fastest is v4

### decrypt
- v3 x 212 ops/sec ±1.08% (81 runs sampled)
- v4 x 2,251 ops/sec ±0.68% (92 runs sampled)

Fastest is v4

### calculateHash
- v3 x 18,807 ops/sec ±3.49% (84 runs sampled)
- v4 x 29,515 ops/sec ±0.78% (89 runs sampled)

Fastest is v4

### extractPublicKey
- v3 x 454 ops/sec ±1.43% (90 runs sampled)
- v4 x 9,054 ops/sec ±0.28% (88 runs sampled)

Fastest is v4

### calculateSignature
- v3 x 425 ops/sec ±1.05% (87 runs sampled)
- v4 x 2,776 ops/sec ±0.80% (91 runs sampled)

Fastest is v4

### verifySignature
- v3 x 437 ops/sec ±0.60% (89 runs sampled)
- v4 x 3,790 ops/sec ±0.37% (90 runs sampled)

Fastest is v4

### signThenEncrypt
- v3 x 145 ops/sec ±0.28% (80 runs sampled)
- v4 x 1,226 ops/sec ±0.89% (93 runs sampled)

Fastest is v4

### decryptThenVerify
- v3 x 143 ops/sec ±0.74% (79 runs sampled)
- v4 x 1,369 ops/sec ±0.37% (92 runs sampled)

Fastest is v4

### getRandomBytes
- v3 x 464 ops/sec ±0.31% (90 runs sampled)
- v4 x 241,286 ops/sec ±3.46% (84 runs sampled)

Fastest is v4

### signThenEncryptDetached
- v3 x 144 ops/sec ±1.51% (80 runs sampled)
- v4 x 1,233 ops/sec ±0.48% (90 runs sampled)

Fastest is v4

### decryptThenVerifyDetached
- v3 x 145 ops/sec ±0.58% (80 runs sampled)
- v4 x 1,354 ops/sec ±0.97% (91 runs sampled)

Fastest is v4

## Browser
### generateKeys
- v3 x 60.06 ops/sec ±0.62% (52 runs sampled)
- v4 x 232 ops/sec ±0.65% (62 runs sampled)

Fastest is v4

### generateKeysFromKeyMaterial
- v3 x 60.59 ops/sec ±0.49% (53 runs sampled)
- v4 x 233 ops/sec ±0.33% (60 runs sampled)

Fastest is v4

### importPrivateKey
- v3 x 87.00 ops/sec ±0.42% (56 runs sampled)
- v4 x 12,685 ops/sec ±0.82% (66 runs sampled)

Fastest is v4

### exportPrivateKey
- v3 x 54,648,205 ops/sec ±0.32% (65 runs sampled)
- v4 x 12,900 ops/sec ±0.45% (65 runs sampled)

Fastest is v3

### importPublicKey
- v3 x 206 ops/sec ±0.93% (60 runs sampled)
- v4 x 180,804 ops/sec ±0.32% (64 runs sampled)

Fastest is v4

### exportPublicKey
- v3 x 883,385,947 ops/sec ±0.52% (66 runs sampled)
- v4 x 1,129,470 ops/sec ±1.07% (66 runs sampled)

Fastest is v3

### encrypt
- v3 x 63.63 ops/sec ±0.55% (48 runs sampled)
- v4 x 3,253 ops/sec ±1.98% (21 runs sampled)

Fastest is v4

### decrypt
- v3 x 65.89 ops/sec ±1.18% (49 runs sampled)
- v4 x 3,426 ops/sec ±1.02% (22 runs sampled)

Fastest is v4

### calculateHash
- v3 x 3,861 ops/sec ±2.66% (60 runs sampled)
- v4 x 150,379 ops/sec ±1.54% (61 runs sampled)

Fastest is v4

### extractPublicKey
- v3 x 166 ops/sec ±3.76% (57 runs sampled)
- v4 x 13,296 ops/sec ±0.96% (63 runs sampled)

Fastest is v4

### calculateSignature
- v3 x 125 ops/sec ±1.14% (58 runs sampled)
- v4 x 4,297 ops/sec ±1.81% (26 runs sampled)

Fastest is v4

### verifySignature
- v3 x 118 ops/sec ±0.49% (55 runs sampled)
- v4 x 5,604 ops/sec ±0.44% (63 runs sampled)

Fastest is v4

### signThenEncrypt
- v3 x 44.69 ops/sec ±1.53% (47 runs sampled)
- v4 x 1,819 ops/sec ±0.57% (64 runs sampled)

Fastest is v4

### decryptThenVerify
- v3 x 43.86 ops/sec ±0.39% (47 runs sampled)
- v4 x 2,075 ops/sec ±0.94% (15 runs sampled)

Fastest is v4

### getRandomBytes
- v3 x 219 ops/sec ±0.53% (62 runs sampled)
- v4 x 259,039 ops/sec ±2.31% (61 runs sampled)

Fastest is v4

### signThenEncryptDetached
- v3 x 45.43 ops/sec ±0.36% (48 runs sampled)
- v4 x 1,819 ops/sec ±0.47% (64 runs sampled)

Fastest is v4

### decryptThenVerifyDetached
- v3 x 43.85 ops/sec ±0.31% (47 runs sampled)
- v4 x 2,078 ops/sec ±1.62% (15 runs sampled)

Fastest is v4
