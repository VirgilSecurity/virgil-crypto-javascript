import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';

import { setFoundationModules, VirgilCrypto, VirgilPrivateKey } from '..';

describe('VirgilStreamDecipher', () => {
  let virgilCrypto: VirgilCrypto;

  beforeEach(() => {
    return new Promise(resolve => {
      initFoundation().then(foundationModules => {
        setFoundationModules(foundationModules);
        virgilCrypto = new VirgilCrypto();
        resolve();
      });
    });
  });

  it('throws if private key is invalid', () => {
    const error = () => {
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
