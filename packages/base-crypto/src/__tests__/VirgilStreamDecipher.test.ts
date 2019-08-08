import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';

import { initBaseCrypto } from '../initBaseCrypto';
import { VirgilCryptoType } from '../initVirgilCrypto';
import { VirgilPrivateKey } from '../VirgilPrivateKey';

describe('VirgilStreamDecipher', () => {
  let virgilCrypto: VirgilCryptoType;

  beforeEach(() => {
    return new Promise(resolve => {
      initFoundation().then(foundationModules => {
        const baseCrypto = initBaseCrypto(foundationModules);
        virgilCrypto = new baseCrypto.VirgilCrypto();
        resolve();
      });
    });
  });

  it('throws if private key is invalid', () => {
    const error = () => {
      // eslint-disable-next-line @typescript-eslint/no-object-literal-type-assertion
      virgilCrypto.createStreamDecipher({} as VirgilPrivateKey);
    };
    expect(error).to.throw;
  });

  it('throws if update is called after final', () => {
    const keyPair = virgilCrypto.generateKeys();
    const encrypted = virgilCrypto.encrypt({ value: 'data', encoding: 'utf8' }, keyPair.publicKey);
    const streamDecipher = virgilCrypto.createStreamDecipher(keyPair.privateKey);
    streamDecipher.update(encrypted);
    streamDecipher.final(false);
    const error = () => {
      streamDecipher.update(encrypted);
    };
    expect(error).to.throw;
    streamDecipher.dispose();
  });

  it('throws if final is called after final', () => {
    const keyPair = virgilCrypto.generateKeys();
    const encrypted = virgilCrypto.encrypt({ value: 'data', encoding: 'utf8' }, keyPair.publicKey);
    const streamDecipher = virgilCrypto.createStreamDecipher(keyPair.privateKey);
    streamDecipher.update(encrypted);
    streamDecipher.final(false);
    const error = () => {
      streamDecipher.final();
    };
    expect(error).to.throw;
    streamDecipher.dispose();
  });

  it('throws if not signed', () => {
    const keyPair = virgilCrypto.generateKeys();
    const encrypted = virgilCrypto.encrypt({ value: 'data', encoding: 'utf8' }, keyPair.publicKey);
    const streamDecipher = virgilCrypto.createStreamDecipher(keyPair.privateKey);
    streamDecipher.update(encrypted);
    streamDecipher.final(false);
    const error = () => {
      streamDecipher.getSignature();
    };
    expect(error).to.throw;
    streamDecipher.dispose();
  });

  it('throws if update is called after object was disposed', () => {
    const keyPair = virgilCrypto.generateKeys();
    const encrypted = virgilCrypto.encrypt({ value: 'data', encoding: 'utf8' }, keyPair.publicKey);
    const streamDecipher = virgilCrypto.createStreamDecipher(keyPair.privateKey);
    streamDecipher.dispose();
    const error = () => {
      streamDecipher.update(encrypted);
    };
    expect(error).to.throw;
  });

  it('throws if final is called after object was disposed', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamDecipher = virgilCrypto.createStreamDecipher(keyPair.privateKey);
    streamDecipher.dispose();
    const error = () => {
      streamDecipher.final();
    };
    expect(error).to.throw;
  });
});
