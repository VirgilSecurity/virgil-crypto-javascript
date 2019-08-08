import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';

import { initBaseCrypto } from '../initBaseCrypto';
import { VirgilCryptoType } from '../initVirgilCrypto';

describe('VirgilStreamSigner', () => {
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

  it('throws if sign is called more than once by default', () => {
    const streamSigner = virgilCrypto.createStreamSigner();
    const keyPair1 = virgilCrypto.generateKeys();
    const keyPair2 = virgilCrypto.generateKeys();
    streamSigner.update({ value: 'data', encoding: 'utf8' });
    streamSigner.sign(keyPair1.privateKey);
    const error = () => {
      streamSigner.sign(keyPair2.privateKey);
    };
    expect(error).to.throw;
  });

  it('sign can be called more than once if `final` is `false`', () => {
    const streamSigner = virgilCrypto.createStreamSigner();
    const keyPair1 = virgilCrypto.generateKeys();
    const keyPair2 = virgilCrypto.generateKeys();
    streamSigner.update({ value: 'data', encoding: 'utf8' });
    streamSigner.sign(keyPair1.privateKey, false);
    const error = () => {
      streamSigner.sign(keyPair2.privateKey);
    };
    expect(error).not.to.throw;
    streamSigner.dispose();
  });

  it('throws if update is called after object was disposed', () => {
    const streamSigner = virgilCrypto.createStreamSigner();
    streamSigner.dispose();
    const error = () => {
      streamSigner.update({ value: 'data', encoding: 'utf8' });
    };
    expect(error).to.throw;
  });
});
