import { expect } from 'chai';

import { NodeBuffer } from '@virgilsecurity/data-utils';

import { initCrypto } from '../foundationModules';
import { NodeBuffer as BufferType } from '../types';
import { VirgilCrypto } from '../VirgilCrypto';

describe.only('VirgilStreamSignAndEncrypt', () => {
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
    const stream = virgilCrypto.createStreamSignAndEncrypt(
      keyPair1.privateKey,
      [keyPair1.publicKey, keyPair2.publicKey],
      true,
    );
    const buffers = new Array<BufferType>();
    buffers.push(stream.start(data.length));
    buffers.push(stream.update(data));
    buffers.push(stream.final(true));
    const encryptedData = NodeBuffer.concat(buffers);
    const decryptedData = virgilCrypto.decryptAndVerify(encryptedData, keyPair2.privateKey, [
      keyPair1.publicKey,
      keyPair2.publicKey,
    ]);
    const error1 = () => {
      virgilCrypto.decryptAndVerify(encryptedData, keyPair3.privateKey, [
        keyPair1.publicKey,
        keyPair2.publicKey,
      ]);
    };
    const error2 = () => {
      virgilCrypto.decryptAndVerify(encryptedData, keyPair2.privateKey, keyPair3.publicKey);
    };
    expect(decryptedData.equals(data)).to.be.true;
    expect(error1).to.throw;
    expect(error2).to.throw;
  });
});
