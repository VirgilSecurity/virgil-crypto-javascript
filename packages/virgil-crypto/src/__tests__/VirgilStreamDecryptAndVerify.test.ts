import { expect } from 'chai';

import { NodeBuffer } from '@virgilsecurity/data-utils';

import { initCrypto } from '../foundationModules';
import { NodeBuffer as BufferType } from '../types';
import { VirgilCrypto } from '../VirgilCrypto';

describe('VirgilStreamDecryptAndVerify', () => {
  let virgilCrypto: VirgilCrypto;

  before(async () => {
    await initCrypto();
  });

  beforeEach(() => {
    virgilCrypto = new VirgilCrypto();
  });

  it('works', () => {
    const data = NodeBuffer.from('data', 'utf8');
    const keyPair1 = virgilCrypto.generateKeys();
    const keyPair2 = virgilCrypto.generateKeys();
    const keyPair3 = virgilCrypto.generateKeys();
    const encryptedData = virgilCrypto.signAndEncrypt(data, keyPair1.privateKey, [
      keyPair1.publicKey,
      keyPair2.publicKey,
    ]);
    const stream = virgilCrypto.createStreamDecryptAndVerify();
    const buffers = new Array<BufferType>();
    stream.start(keyPair1.privateKey);
    buffers.push(stream.update(encryptedData));
    buffers.push(stream.final());
    const decrypted = NodeBuffer.concat(buffers);
    const notAnError = () => {
      stream.verify([keyPair1.publicKey, keyPair2.publicKey], false);
    };
    const error = () => {
      stream.verify(keyPair3.publicKey);
    };
    expect(decrypted.equals(data)).to.be.true;
    expect(notAnError).not.to.throw;
    expect(error).to.throw;
  });
});
