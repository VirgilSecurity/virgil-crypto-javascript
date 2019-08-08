import { initCrypto } from 'virgil-crypto';

initCrypto().then(({ VirgilCrypto }) => {
  const virgilCrypto = new VirgilCrypto();
  const keys = virgilCrypto.generateKeys();
  const data = 'data';
  const encrypted = virgilCrypto.encrypt({ value: data, encoding: 'utf8' }, keys.publicKey);
  const decrypted = virgilCrypto.decrypt(encrypted, keys.privateKey);
  console.log(data);
  console.log(decrypted.toString());
});
