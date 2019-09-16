# Benchmarks
## Node.js
### generateKeys
- v3 x 143 ops/sec ±2.27% (79 runs sampled)
- v4 x 245 ops/sec ±2.56% (81 runs sampled)

Fastest is v4

### generateKeysFromKeyMaterial
- v3 x 153 ops/sec ±0.57% (84 runs sampled)
- v4 x 245 ops/sec ±2.78% (81 runs sampled)

Fastest is v4

### importPrivateKey
- v3 x 224 ops/sec ±1.79% (86 runs sampled)
- v4 x 8,079 ops/sec ±1.01% (88 runs sampled)

Fastest is v4

### exportPrivateKey
- v3 x 29,272,543 ops/sec ±0.42% (91 runs sampled)
- v4 x 8,908 ops/sec ±0.41% (91 runs sampled)

Fastest is v3

### importPublicKey
- v3 x 439 ops/sec ±0.78% (88 runs sampled)
- v4 x 76,792 ops/sec ±1.09% (93 runs sampled)

Fastest is v4

### exportPublicKey
- v3 x 89,431,724 ops/sec ±0.23% (87 runs sampled)
- v4 x 4,099,616 ops/sec ±1.07% (96 runs sampled)

Fastest is v3

### encrypt
- v3 x 225 ops/sec ±0.19% (86 runs sampled)
- v4 x 2,358 ops/sec ±0.51% (91 runs sampled)

Fastest is v4

### decrypt
- v3 x 226 ops/sec ±0.11% (86 runs sampled)
- v4 x 2,310 ops/sec ±0.38% (94 runs sampled)

Fastest is v4

### calculateHash
- v3 x 19,162 ops/sec ±3.65% (86 runs sampled)
- v4 x 29,848 ops/sec ±0.75% (94 runs sampled)

Fastest is v4

### extractPublicKey
- v3 x 468 ops/sec ±0.24% (92 runs sampled)
- v4 x 9,124 ops/sec ±0.19% (95 runs sampled)

Fastest is v4

### calculateSignature
- v3 x 452 ops/sec ±0.13% (93 runs sampled)
- v4 x 2,816 ops/sec ±0.76% (93 runs sampled)

Fastest is v4

### verifySignature
- v3 x 450 ops/sec ±0.11% (92 runs sampled)
- v4 x 3,837 ops/sec ±0.21% (94 runs sampled)

Fastest is v4

### signThenEncrypt
- v3 x 149 ops/sec ±0.17% (82 runs sampled)
- v4 x 1,265 ops/sec ±0.23% (95 runs sampled)

Fastest is v4

### decryptThenVerify
- v3 x 149 ops/sec ±0.19% (82 runs sampled)
- v4 x 1,393 ops/sec ±0.81% (94 runs sampled)

Fastest is v4

### getRandomBytes
- v3 x 476 ops/sec ±0.13% (91 runs sampled)
- v4 x 248,174 ops/sec ±2.16% (87 runs sampled)

Fastest is v4

### signThenEncryptDetached
- v3 x 149 ops/sec ±0.11% (82 runs sampled)
- v4 x 1,263 ops/sec ±0.31% (95 runs sampled)

Fastest is v4

### decryptThenVerifyDetached
- v3 x 149 ops/sec ±0.23% (82 runs sampled)
- v4 x 1,391 ops/sec ±0.29% (94 runs sampled)

Fastest is v4

## Browser
### generateKeys
- v3 x 62.69 ops/sec ±0.51% (54 runs sampled)
- v4 x 236 ops/sec ±0.53% (63 runs sampled)

Fastest is v4

### generateKeysFromKeyMaterial
- v3 x 62.51 ops/sec ±0.86% (54 runs sampled)
- v4 x 238 ops/sec ±0.33% (61 runs sampled)

Fastest is v4

### importPrivateKey
- v3 x 90.10 ops/sec ±0.38% (58 runs sampled)
- v4 x 12,864 ops/sec ±1.03% (65 runs sampled)

Fastest is v4

### exportPrivateKey
- v3 x 55,501,416 ops/sec ±0.18% (67 runs sampled)
- v4 x 13,022 ops/sec ±0.46% (66 runs sampled)

Fastest is v3

### importPublicKey
- v3 x 215 ops/sec ±0.96% (61 runs sampled)
- v4 x 164,862 ops/sec ±4.62% (57 runs sampled)

Fastest is v4

### exportPublicKey
- v3 x 803,946,537 ops/sec ±2.83% (58 runs sampled)
- v4 x 1,083,430 ops/sec ±3.26% (59 runs sampled)

Fastest is v3

### encrypt
- v3 x 59.53 ops/sec ±4.67% (44 runs sampled)
- v4 x 3,131 ops/sec ±3.99% (21 runs sampled)

Fastest is v4

### decrypt
- v3 x 71.27 ops/sec ±0.75% (53 runs sampled)
- v4 x 3,470 ops/sec ±1.44% (22 runs sampled)

Fastest is v4

### calculateHash
- v3 x 3,797 ops/sec ±8.05% (23 runs sampled)
- v4 x 112,825 ops/sec ±9.42% (47 runs sampled)

Fastest is v4

### extractPublicKey
- v3 x 139 ops/sec ±6.60% (47 runs sampled)
- v4 x 12,709 ops/sec ±3.39% (60 runs sampled)

Fastest is v4

### calculateSignature
- v3 x 117 ops/sec ±5.11% (55 runs sampled)
- v4 x 4,224 ops/sec ±2.53% (26 runs sampled)

Fastest is v4

### verifySignature
- v3 x 117 ops/sec ±1.75% (55 runs sampled)
- v4 x 5,437 ops/sec ±1.50% (63 runs sampled)

Fastest is v4

### signThenEncrypt
- v3 x 38.40 ops/sec ±5.03% (41 runs sampled)
- v4 x 1,738 ops/sec ±3.25% (62 runs sampled)

Fastest is v4

### decryptThenVerify
- v3 x 38.14 ops/sec ±1.25% (48 runs sampled)
- v4 x 2,077 ops/sec ±0.49% (65 runs sampled)

Fastest is v4

### getRandomBytes
- v3 x 209 ops/sec ±1.43% (59 runs sampled)
- v4 x 243,733 ops/sec ±2.81% (58 runs sampled)

Fastest is v4

### signThenEncryptDetached
- v3 x 40.18 ops/sec ±0.91% (43 runs sampled)
- v4 x 1,854 ops/sec ±0.68% (65 runs sampled)

Fastest is v4

### decryptThenVerifyDetached
- v3 x 37.74 ops/sec ±1.61% (40 runs sampled)
- v4 x 2,007 ops/sec ±1.80% (60 runs sampled)

Fastest is v4
