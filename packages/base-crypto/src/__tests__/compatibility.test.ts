import { expect } from 'chai';

import initWasmFoundation from '@virgilsecurity/core-foundation';
import initAsmjsFoundation from '@virgilsecurity/core-foundation/node.asmjs.cjs';

import { initBaseCrypto } from '../initBaseCrypto';
import { VirgilCryptoType } from '../initVirgilCrypto';

describe('compatibility', () => {
  let wasmVirgilCrypto: VirgilCryptoType;
  let asmjsVirgilCrypto: VirgilCryptoType;

  beforeEach(() => {
    return new Promise(resolve => {
      Promise.all([initWasmFoundation(), initAsmjsFoundation()]).then(
        ([wasmModules, asmjsModules]) => {
          const wasmCryptoModules = initBaseCrypto(wasmModules);
          const asmjsCryptoModules = initBaseCrypto(asmjsModules);
          wasmVirgilCrypto = new wasmCryptoModules.VirgilCrypto();
          asmjsVirgilCrypto = new asmjsCryptoModules.VirgilCrypto();
          resolve();
        },
      );
    });
  });

  it('encrypts with WebAssembly and decrypts with asm.js', () => {
    const data = 'data';
    const keyPair = wasmVirgilCrypto.generateKeys();
    const exportedPrivateKey = wasmVirgilCrypto.exportPrivateKey(keyPair.privateKey);
    const privateKey = asmjsVirgilCrypto.importPrivateKey(exportedPrivateKey);
    const encryptedData = wasmVirgilCrypto.encrypt(
      { value: data, encoding: 'utf8' },
      keyPair.publicKey,
    );
    const decryptedData = asmjsVirgilCrypto.decrypt(encryptedData, privateKey);
    expect(decryptedData.toString()).to.equal(data);
  });

  it('encrypts with asm.js and decrypts with WebAssembly', () => {
    const data = 'data';
    const keyPair = asmjsVirgilCrypto.generateKeys();
    const exportedPrivateKey = asmjsVirgilCrypto.exportPrivateKey(keyPair.privateKey);
    const privateKey = wasmVirgilCrypto.importPrivateKey(exportedPrivateKey);
    const encryptedData = asmjsVirgilCrypto.encrypt(
      { value: data, encoding: 'utf8' },
      keyPair.publicKey,
    );
    const decryptedData = wasmVirgilCrypto.decrypt(encryptedData, privateKey);
    expect(decryptedData.toString()).to.equal(data);
  });
});
