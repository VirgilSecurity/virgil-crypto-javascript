import { expect } from 'chai';

import initWasmFoundation from '@virgilsecurity/core-foundation';
import initAsmjsFoundation from '@virgilsecurity/core-foundation/node.asmjs.cjs';

import { setFoundationModules, VirgilCrypto } from '..';

describe('compatibility', () => {
  let wasmFoundationModules: typeof FoundationModules;
  let asmjsFoundationModules: typeof FoundationModules;

  before(() => {
    return new Promise(resolve => {
      Promise.all([initWasmFoundation(), initAsmjsFoundation()]).then(
        ([wasmModules, asmjsModules]) => {
          wasmFoundationModules = wasmModules;
          asmjsFoundationModules = asmjsModules;
          resolve();
        },
      );
    });
  });

  it('encrypts with WebAssembly and decrypts with asm.js', () => {
    const data = 'data';

    setFoundationModules(wasmFoundationModules);
    const wasmVirgilCrypto = new VirgilCrypto();
    const keyPair = wasmVirgilCrypto.generateKeys();
    const exportedPrivateKey = wasmVirgilCrypto.exportPrivateKey(keyPair.privateKey);
    const encryptedData = wasmVirgilCrypto.encrypt(
      { value: data, encoding: 'utf8' },
      keyPair.publicKey,
    );

    setFoundationModules(asmjsFoundationModules);
    const asmjsVirgilCrypto = new VirgilCrypto();
    const privateKey = asmjsVirgilCrypto.importPrivateKey(exportedPrivateKey);
    const decryptedData = asmjsVirgilCrypto.decrypt(encryptedData, privateKey);
    expect(decryptedData.toString()).to.equal(data);
  });

  it('encrypts with asm.js and decrypts with WebAssembly', () => {
    const data = 'data';

    setFoundationModules(asmjsFoundationModules);
    const asmjsVirgilCrypto = new VirgilCrypto();
    const keyPair = asmjsVirgilCrypto.generateKeys();
    const exportedPrivateKey = asmjsVirgilCrypto.exportPrivateKey(keyPair.privateKey);
    const encryptedData = asmjsVirgilCrypto.encrypt(
      { value: data, encoding: 'utf8' },
      keyPair.publicKey,
    );

    setFoundationModules(wasmFoundationModules);
    const wasmVirgilCrypto = new VirgilCrypto();
    const privateKey = wasmVirgilCrypto.importPrivateKey(exportedPrivateKey);
    const decryptedData = wasmVirgilCrypto.decrypt(encryptedData, privateKey);
    expect(decryptedData.toString()).to.equal(data);
  });
});
