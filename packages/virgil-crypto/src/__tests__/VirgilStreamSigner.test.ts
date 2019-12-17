import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';

import { hasFoundationModules, setFoundationModules } from '../foundationModules';
import { VirgilCrypto } from '../VirgilCrypto';

describe('VirgilStreamSigner', () => {
  let virgilCrypto: VirgilCrypto;

  before(() => {
    return new Promise(resolve => {
      if (hasFoundationModules()) {
        virgilCrypto = new VirgilCrypto();
        return resolve();
      }

      initFoundation().then(foundationModules => {
        setFoundationModules(foundationModules);
        virgilCrypto = new VirgilCrypto();
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
