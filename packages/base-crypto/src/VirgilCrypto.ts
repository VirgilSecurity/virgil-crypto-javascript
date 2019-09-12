import { FoundationModules } from '@virgilsecurity/core-foundation';
import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { HashAlgorithm, HashAlgorithmType } from './HashAlgorithm';
import { KeyPairType, KeyPairTypeType } from './KeyPairType';
import { importPrivateKey, importPublicKey } from './keyProvider';
import { serializePrivateKey, serializePublicKey } from './keySerializer';
import { getLowLevelPrivateKey } from './privateKeyUtils';
import { ICrypto, Data, LowLevelPrivateKey, LowLevelPublicKey } from './types';
import { toArray } from './utils';
import { validatePrivateKey, validatePublicKey, validatePublicKeysArray } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';
import { VirgilStreamCipher } from './VirgilStreamCipher';
import { VirgilStreamDecipher } from './VirgilStreamDecipher';
import { VirgilStreamSigner } from './VirgilStreamSigner';
import { VirgilStreamVerifier } from './VirgilStreamVerifier';

export interface VirgilCryptoOptions {
  useSha256Identifiers?: boolean;
  defaultKeyPairType?: KeyPairTypeType[keyof KeyPairTypeType];
}

export class VirgilCrypto implements ICrypto {
  readonly useSha256Identifiers: boolean;
  readonly defaultKeyPairType: KeyPairTypeType[keyof KeyPairTypeType];

  readonly hashAlgorithm = HashAlgorithm;
  readonly keyPairType = KeyPairType;

  private foundationModules: FoundationModules;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private random: any;

  constructor(options: VirgilCryptoOptions = {}) {
    this.foundationModules = getFoundationModules();
    this.defaultKeyPairType = options.defaultKeyPairType || KeyPairType.Default;
    this.useSha256Identifiers = options.useSha256Identifiers || false;
    this.random = new this.foundationModules.CtrDrbg();
    this.random.setupDefaults();
  }

  generateKeys(type?: KeyPairTypeType[keyof KeyPairTypeType]) {
    const keyPairType = type ? type : this.defaultKeyPairType;

    const keyProvider = new this.foundationModules.KeyProvider();
    keyProvider.setupDefaults();
    if (keyPairType.algId === this.foundationModules.AlgId.RSA) {
      keyProvider.setRsaParams(keyPairType.bitlen);
    }

    const lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();
    const keyPair = this.wrapKeyPair(
      lowLevelPrivateKey,
      lowLevelPublicKey,
      this.useSha256Identifiers,
    );

    keyProvider.delete();
    lowLevelPrivateKey.delete();
    lowLevelPublicKey.delete();

    return keyPair;
  }

  generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairTypeType[keyof KeyPairTypeType]) {
    const keyPairType = type ? type : this.defaultKeyPairType;
    const myKeyMaterial = dataToUint8Array(keyMaterial, 'base64');

    const keyMaterialRng = new this.foundationModules.KeyMaterialRng();
    keyMaterialRng.resetKeyMaterial(myKeyMaterial);

    const keyProvider = new this.foundationModules.KeyProvider();
    keyProvider.setupDefaults();
    keyProvider.random = keyMaterialRng;
    if (keyPairType.algId === this.foundationModules.AlgId.RSA) {
      keyProvider.setRsaParams(keyPairType.bitlen);
    }

    const lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();
    const keyPair = this.wrapKeyPair(
      lowLevelPrivateKey,
      lowLevelPublicKey,
      this.useSha256Identifiers,
    );

    keyMaterialRng.delete();
    keyProvider.delete();
    lowLevelPrivateKey.delete();
    lowLevelPublicKey.delete();

    return keyPair;
  }

  importPrivateKey(rawPrivateKey: Data) {
    const myRawPrivateKey = dataToUint8Array(rawPrivateKey, 'base64');

    const lowLevelPrivateKey = importPrivateKey(myRawPrivateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    const serializedPublicKey = serializePublicKey(lowLevelPublicKey);
    const identifier = this.calculateKeypairIdentifier(
      serializedPublicKey,
      this.useSha256Identifiers,
    );
    const virgilPrivateKey = new VirgilPrivateKey(identifier, lowLevelPrivateKey);

    lowLevelPrivateKey.delete();
    lowLevelPublicKey.delete();

    return virgilPrivateKey;
  }

  exportPrivateKey(privateKey: VirgilPrivateKey) {
    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);
    const serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
    return toBuffer(serializedPrivateKey);
  }

  importPublicKey(rawPublicKey: Data) {
    const myRawPublicKey = dataToUint8Array(rawPublicKey, 'base64');

    const lowLevelPublicKey = importPublicKey(myRawPublicKey);

    const serializedKey = serializePublicKey(lowLevelPublicKey);
    const identifier = this.calculateKeypairIdentifier(serializedKey, this.useSha256Identifiers);
    const virgilPublicKey = new VirgilPublicKey(identifier, lowLevelPublicKey);

    lowLevelPublicKey.delete();

    return virgilPublicKey;
  }

  exportPublicKey(publicKey: VirgilPublicKey) {
    return toBuffer(publicKey.key);
  }

  encrypt(data: Data, publicKey: VirgilPublicKey | VirgilPublicKey[]) {
    const myData = dataToUint8Array(data, 'utf8');
    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const lowLevelPublicKeys = publicKeys.map(publicKey => importPublicKey(publicKey.key));

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, lowLevelPublicKeys[index]);
    });

    recipientCipher.startEncryption();
    const messageInfo = recipientCipher.packMessageInfo();
    const processEncryption = recipientCipher.processEncryption(myData);
    const finishEncryption = recipientCipher.finishEncryption();

    recipientCipher.delete();
    aes256Gcm.delete();
    lowLevelPublicKeys.forEach(lowLevelPublicKey => {
      lowLevelPublicKey.delete();
    });

    return NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
  }

  decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
    const myData = dataToUint8Array(encryptedData, 'base64');
    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

    recipientCipher.startDecryptionWithKey(
      privateKey.identifier,
      lowLevelPrivateKey,
      new Uint8Array(0),
    );
    const processDecryption = recipientCipher.processDecryption(myData);
    const finishDecryption = recipientCipher.finishDecryption();

    recipientCipher.delete();
    lowLevelPrivateKey.delete();

    return NodeBuffer.concat([processDecryption, finishDecryption]);
  }

  calculateHash(
    data: Data,
    algorithm: HashAlgorithmType[keyof HashAlgorithmType] = HashAlgorithm.SHA512,
  ) {
    const myData = dataToUint8Array(data, 'utf8');
    let result: Uint8Array;
    switch (algorithm) {
      case HashAlgorithm.SHA224:
        result = this.createHash(myData, this.foundationModules.Sha224);
        break;
      case HashAlgorithm.SHA256:
        result = this.createHash(myData, this.foundationModules.Sha256);
        break;
      case HashAlgorithm.SHA384:
        result = this.createHash(myData, this.foundationModules.Sha384);
        break;
      case HashAlgorithm.SHA512:
        result = this.createHash(myData, this.foundationModules.Sha512);
        break;
      default:
        throw new TypeError('Unknown hash algorithm');
    }
    return toBuffer(result);
  }

  extractPublicKey(privateKey: VirgilPrivateKey) {
    validatePrivateKey(privateKey);

    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();
    const virgilPublicKey = new VirgilPublicKey(privateKey.identifier, lowLevelPublicKey);

    lowLevelPrivateKey.delete();
    lowLevelPublicKey.delete();

    return virgilPublicKey;
  }

  calculateSignature(data: Data, privateKey: VirgilPrivateKey) {
    const myData = dataToUint8Array(data, 'utf8');
    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const signer = new this.foundationModules.Signer();
    const sha512 = new this.foundationModules.Sha512();
    signer.hash = sha512;

    signer.reset();
    signer.appendData(myData);
    const signature = signer.sign(lowLevelPrivateKey);

    signer.delete();
    sha512.delete();
    lowLevelPrivateKey.delete();

    return toBuffer(signature);
  }

  verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
    const myData = dataToUint8Array(data, 'utf8');
    const mySignature = dataToUint8Array(signature, 'base64');
    validatePublicKey(publicKey);

    const verifier = new this.foundationModules.Verifier();

    verifier.reset(mySignature);
    verifier.appendData(myData);

    const lowLevelPublicKey = importPublicKey(publicKey.key);
    const result = verifier.verify(lowLevelPublicKey);

    verifier.delete();
    lowLevelPublicKey.delete();

    return result;
  }

  signThenEncrypt(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);
    const lowLevelPublicKeys = publicKeys.map(publicKey => importPublicKey(publicKey.key));

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

    const signature = this.calculateSignature(myData, privateKey);
    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, lowLevelPublicKeys[index]);
    });

    const messageInfoCustomParams = recipientCipher.customParams();
    messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, signature);
    messageInfoCustomParams.addData(DATA_SIGNER_ID_KEY, privateKey.identifier);

    recipientCipher.startEncryption();
    const messageInfo = recipientCipher.packMessageInfo();
    const processEncryption = recipientCipher.processEncryption(myData);
    const finishEncryption = recipientCipher.finishEncryption();

    const result = NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);;

    recipientCipher.delete();
    aes256Gcm.delete();
    messageInfoCustomParams.delete();
    lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());

    return result;
  }

  decryptThenVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

    recipientCipher.startDecryptionWithKey(
      privateKey.identifier,
      lowLevelPrivateKey,
      new Uint8Array(0),
    );
    const processDecryption = recipientCipher.processDecryption(myEncryptedData);
    const finishDecryption = recipientCipher.finishDecryption();
    const decryptedData = NodeBuffer.concat([processDecryption, finishDecryption]);

    const messageInfoCustomParams = recipientCipher.customParams();

    let signerPublicKey: VirgilPublicKey | undefined;
    if (publicKeys.length === 1) {
      signerPublicKey = publicKeys[0];
    } else {
      const signerId = messageInfoCustomParams.findData(DATA_SIGNER_ID_KEY);
      for (let i = 0; i < publicKeys.length; i += 1) {
        if (NodeBuffer.compare(signerId, publicKeys[i].identifier) === 0) {
          signerPublicKey = publicKeys[i];
          break;
        }
      }
      if (!signerPublicKey) {
        throw new Error('Signer not found');
      }
    }

    const signature = messageInfoCustomParams.findData(DATA_SIGNATURE_KEY);

    const isValid = this.verifySignature(decryptedData, signature, signerPublicKey);
    if (!isValid) {
      throw new Error('Invalid signature');
    }

    recipientCipher.delete();
    messageInfoCustomParams.delete();
    lowLevelPrivateKey.delete();

    return decryptedData;
  }

  getRandomBytes(length: number) {
    const bytes = this.random.random(length);
    return toBuffer(bytes);
  }

  signThenEncryptDetached(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);
    const lowLevelPublicKeys = publicKeys.map(publicKey => importPublicKey(publicKey.key));

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

    const signature = this.calculateSignature(myData, privateKey);
    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, lowLevelPublicKeys[index]);
    });

    const messageInfoCustomParams = recipientCipher.customParams();
    messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, signature);
    messageInfoCustomParams.addData(DATA_SIGNER_ID_KEY, privateKey.identifier);

    recipientCipher.startEncryption();
    const messageInfo = recipientCipher.packMessageInfo();
    const processEncryption = recipientCipher.processEncryption(myData);
    const finishEncryption = recipientCipher.finishEncryption();

    recipientCipher.delete();
    aes256Gcm.delete();
    messageInfoCustomParams.delete();
    lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());

    return {
      encryptedData: NodeBuffer.concat([processEncryption, finishEncryption]),
      metadata: toBuffer(messageInfo),
    };
  }

  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');
    const myMetadata = dataToUint8Array(metadata, 'base64');

    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

    recipientCipher.startDecryptionWithKey(privateKey.identifier, lowLevelPrivateKey, myMetadata);
    const processDecryption = recipientCipher.processDecryption(myEncryptedData);
    const finishDecryption = recipientCipher.finishDecryption();
    const decryptedData = NodeBuffer.concat([processDecryption, finishDecryption]);

    const messageInfoCustomParams = recipientCipher.customParams();

    let signerPublicKey: VirgilPublicKey | undefined;
    if (publicKeys.length === 1) {
      signerPublicKey = publicKeys[0];
    } else {
      const signerId = messageInfoCustomParams.findData(DATA_SIGNER_ID_KEY);
      for (let i = 0; i < publicKeys.length; i += 1) {
        if (NodeBuffer.compare(signerId, publicKeys[i].identifier) === 0) {
          signerPublicKey = publicKeys[i];
          break;
        }
      }
      if (!signerPublicKey) {
        throw new Error('Signer not found');
      }
    }

    const signature = messageInfoCustomParams.findData(DATA_SIGNATURE_KEY);

    const isValid = this.verifySignature(decryptedData, signature, signerPublicKey);
    if (!isValid) {
      throw new Error('Invalid signature');
    }

    recipientCipher.delete();
    messageInfoCustomParams.delete();
    lowLevelPrivateKey.delete();

    return decryptedData;
  }

  createStreamCipher(publicKey: VirgilPublicKey | VirgilPublicKey[], signature?: Data) {
    return new VirgilStreamCipher(publicKey, signature);
  }

  createStreamDecipher(privateKey: VirgilPrivateKey) {
    return new VirgilStreamDecipher(privateKey);
  }

  createStreamSigner() {
    return new VirgilStreamSigner();
  }

  createStreamVerifier(signature: Data) {
    return new VirgilStreamVerifier(signature);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private createHash(data: Uint8Array, HashClass: any) {
    const hashInstance = new HashClass();
    const hash = hashInstance.hash(data);
    hashInstance.delete();
    return hash;
  }

  private calculateKeypairIdentifier(
    serializedPublicKey: Uint8Array,
    useSha256Identifiers: boolean,
  ) {
    if (useSha256Identifiers) {
      return this.createHash(serializedPublicKey, this.foundationModules.Sha256);
    }
    return this.createHash(serializedPublicKey, this.foundationModules.Sha512).slice(0, 8);
  }

  private wrapKeyPair(
    lowLevelPrivateKey: LowLevelPrivateKey,
    lowLevelPublicKey: LowLevelPublicKey,
    useSha256Identifiers: boolean,
  ) {
    const serializedPublicKey = serializePublicKey(lowLevelPublicKey);
    const identifier = this.calculateKeypairIdentifier(serializedPublicKey, useSha256Identifiers);
    return {
      privateKey: new VirgilPrivateKey(identifier, lowLevelPrivateKey),
      publicKey: new VirgilPublicKey(identifier, lowLevelPublicKey),
    };
  }
}
