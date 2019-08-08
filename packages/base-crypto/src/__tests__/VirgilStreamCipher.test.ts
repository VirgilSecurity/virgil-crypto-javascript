import { expect } from 'chai';

import initFoundation from '@virgilsecurity/core-foundation';

import { initBaseCrypto } from '../initBaseCrypto';
import { VirgilCryptoType } from '../initVirgilCrypto';
import { VirgilPublicKey } from '../VirgilPublicKey';

describe('VirgilStreamCipher', () => {
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

  it('throws if public keys are invalid', () => {
    const error = () => {
      // eslint-disable-next-line @typescript-eslint/no-object-literal-type-assertion
      virgilCrypto.createStreamCipher({} as VirgilPublicKey);
    };
    expect(error).to.throw;
  });

  it('throws if update is called before start', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    const error = () => {
      streamCipher.update({ value: 'data', encoding: 'utf8' });
    };
    expect(error).to.throw;
    streamCipher.dispose();
  });

  it('throws if final is called before start', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    const error = () => {
      streamCipher.final();
    };
    expect(error).to.throw;
    streamCipher.dispose();
  });

  it('throws if update is called after final', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    streamCipher.start();
    streamCipher.update({ value: 'data', encoding: 'utf8' });
    streamCipher.final();
    const error = () => {
      streamCipher.update({ value: 'data', encoding: 'utf8' });
    };
    expect(error).to.throw;
  });

  it('throws if start is called after final', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    streamCipher.start();
    streamCipher.update({ value: 'data', encoding: 'utf8' });
    streamCipher.final();
    const error = () => {
      streamCipher.start();
    };
    expect(error).to.throw;
  });

  it('throws if final is called after final', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    streamCipher.start();
    streamCipher.update({ value: 'data', encoding: 'utf8' });
    streamCipher.final();
    const error = () => {
      streamCipher.final();
    };
    expect(error).to.throw;
  });

  it('throws if start is called after object was disposed', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    streamCipher.dispose();
    const error = () => {
      streamCipher.start();
    };
    expect(error).to.throw;
  });

  it('throws if update is called after object was disposed', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    streamCipher.dispose();
    const error = () => {
      streamCipher.update({ value: 'data', encoding: 'utf8' });
    };
    expect(error).to.throw;
  });

  it('throws if final is called after object was disposed', () => {
    const keyPair = virgilCrypto.generateKeys();
    const streamCipher = virgilCrypto.createStreamCipher(keyPair.publicKey);
    streamCipher.dispose();
    const error = () => {
      streamCipher.final();
    };
    expect(error).to.throw;
  });
});
