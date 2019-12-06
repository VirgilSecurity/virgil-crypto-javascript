import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';
import { NodeBuffer } from '@virgilsecurity/data-utils';

import { foundationInitializer } from '../foundationModules';
import { VirgilCrypto } from '../VirgilCrypto';

describe('VrigilStreamVerifier', () => {
  let virgilCrypto: VirgilCrypto;

  before(() => {
    return new Promise(resolve => {
      if (foundationInitializer.isInitialized) {
        virgilCrypto = new VirgilCrypto();
        return resolve();
      }

      initFoundation().then(foundationModules => {
        foundationInitializer.module = foundationModules;
        virgilCrypto = new VirgilCrypto();
        resolve();
      });
    });
  });

  it('throws if signature is invalid', () => {
    const error = () => {
      virgilCrypto.createStreamVerifier((undefined as unknown) as Uint8Array);
    };
    expect(error).to.throw;
  });

  it('throws if verify is called more than once by default', () => {
    const keyPair = virgilCrypto.generateKeys();
    const data = NodeBuffer.from('data');
    const signature = virgilCrypto.calculateSignature(data, keyPair.privateKey);
    const streamVerifier = virgilCrypto.createStreamVerifier(signature);
    streamVerifier.update(data);
    streamVerifier.verify(keyPair.publicKey);
    const error = () => {
      streamVerifier.verify(keyPair.publicKey);
    };
    expect(error).to.throw;
  });

  it('verify can be called more that once if `final` is `false`', () => {
    const keyPair = virgilCrypto.generateKeys();
    const data = NodeBuffer.from('data');
    const signature = virgilCrypto.calculateSignature(data, keyPair.privateKey);
    const streamVerifier = virgilCrypto.createStreamVerifier(signature);
    streamVerifier.update(data);
    streamVerifier.verify(keyPair.publicKey, false);
    const error = () => {
      streamVerifier.verify(keyPair.publicKey);
    };
    expect(error).not.to.throw;
  });

  it('throws if update is called after object was disposed', () => {
    const keyPair = virgilCrypto.generateKeys();
    const data = NodeBuffer.from('data');
    const signature = virgilCrypto.calculateSignature(data, keyPair.privateKey);
    const streamVerifier = virgilCrypto.createStreamVerifier(signature);
    streamVerifier.dispose();
    const error = () => {
      streamVerifier.update(data);
    };
    expect(error).to.throw;
  });
});
