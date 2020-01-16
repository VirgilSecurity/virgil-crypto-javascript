import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { createVirgilGroupSession } from './groups/createVirgilGroupSession';
import { computeSessionId, createInitialEpoch } from './groups/helpers';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { HashAlgorithm, HashAlgorithmType } from './HashAlgorithm';
import {
  KeyPairType,
  KeyPairTypeConfig,
  getKeyPairTypeConfig,
  isRSAKeyPairType,
  isCompoundKeyPairType,
} from './KeyPairType';
import { FoundationModules, ICrypto, NodeBuffer as BufferType, Data, IGroupSession } from './types';
import { toArray } from './utils';
import { validatePrivateKey, validatePublicKey, validatePublicKeysArray } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';
import { VirgilStreamCipher } from './VirgilStreamCipher';
import { VirgilStreamDecipher } from './VirgilStreamDecipher';
import { VirgilStreamSigner } from './VirgilStreamSigner';
import { VirgilStreamVerifier } from './VirgilStreamVerifier';

export const MIN_GROUP_ID_BYTE_LENGTH = 10;

export interface VirgilCryptoOptions {
  useSha256Identifiers?: boolean;
  defaultKeyPairType?: KeyPairType;
}

export class VirgilCrypto implements ICrypto {
  static get PADDING_LEN() {
    return 160;
  }

  readonly useSha256Identifiers: boolean;
  readonly defaultKeyPairType: KeyPairType;

  readonly hashAlgorithm = HashAlgorithm;
  readonly keyPairType = KeyPairType;

  private readonly random: FoundationModules.CtrDrbg;
  private _isDisposed: boolean;

  get isDisposed() {
    return this._isDisposed;
  }

  constructor(options: VirgilCryptoOptions = {}) {
    const foundation = getFoundationModules();
    this.random = new foundation.CtrDrbg();
    try {
      this.random.setupDefaults();
    } catch (error) {
      this.random.delete();
      throw error;
    }
    this.defaultKeyPairType = options.defaultKeyPairType || KeyPairType.DEFAULT;
    this.useSha256Identifiers = options.useSha256Identifiers || false;
    this._isDisposed = false;
  }

  dispose() {
    this.random.delete();
    this._isDisposed = true;
  }

  generateKeys(type?: KeyPairType[keyof KeyPairType]) {
    this.throwIfDisposed();
    const keyPairType = type ? type : this.defaultKeyPairType;
    const keyPairTypeConfig = getKeyPairTypeConfig(keyPairType);
    const foundation = getFoundationModules();
    const keyProvider = new foundation.KeyProvider();
    keyProvider.random = this.random;
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    try {
      return this.generateKeyPair(keyProvider, keyPairTypeConfig);
    } finally {
      keyProvider.delete();
    }
  }

  generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairType[keyof KeyPairType]) {
    this.throwIfDisposed();
    const keyPairType = type ? type : this.defaultKeyPairType;
    const keyPairTypeConfig = getKeyPairTypeConfig(keyPairType);
    const myKeyMaterial = dataToUint8Array(keyMaterial, 'base64');
    const foundation = getFoundationModules();
    const keyMaterialRng = new foundation.KeyMaterialRng();
    keyMaterialRng.resetKeyMaterial(myKeyMaterial);
    const keyProvider = new foundation.KeyProvider();
    keyProvider.random = keyMaterialRng;
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyMaterialRng.delete();
      keyProvider.delete();
      throw error;
    }
    try {
      return this.generateKeyPair(keyProvider, keyPairTypeConfig);
    } finally {
      keyMaterialRng.delete();
      keyProvider.delete();
    }
  }

  importPrivateKey(rawPrivateKey: Data) {
    this.throwIfDisposed();
    const foundation = getFoundationModules();
    const keyProvider = new foundation.KeyProvider();
    keyProvider.random = this.random;
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    const serializedPrivateKey = dataToUint8Array(rawPrivateKey, 'base64');
    const lowLevelPrivateKey = keyProvider.importPrivateKey(serializedPrivateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();
    try {
      const serializedPublicKey = keyProvider.exportPublicKey(lowLevelPublicKey);
      const identifier = this.calculateKeyPairIdentifier(serializedPublicKey);
      return new VirgilPrivateKey(identifier, lowLevelPrivateKey);
    } finally {
      lowLevelPublicKey.delete();
      keyProvider.delete();
    }
  }

  exportPrivateKey(privateKey: VirgilPrivateKey) {
    this.throwIfDisposed();
    validatePrivateKey(privateKey);
    const foundation = getFoundationModules();
    const keyProvider = new foundation.KeyProvider();
    keyProvider.random = this.random;
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    const publicKeyData = keyProvider.exportPrivateKey(privateKey.lowLevelPrivateKey);
    keyProvider.delete();
    return toBuffer(publicKeyData);
  }

  importPublicKey(rawPublicKey: Data) {
    this.throwIfDisposed();
    const serializedPublicKey = dataToUint8Array(rawPublicKey, 'base64');
    const foundation = getFoundationModules();
    const keyProvider = new foundation.KeyProvider();
    keyProvider.random = this.random;
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    const lowLevelPublicKey = keyProvider.importPublicKey(serializedPublicKey);
    const identifier = this.calculateKeyPairIdentifier(serializedPublicKey);
    keyProvider.delete();
    return new VirgilPublicKey(identifier, lowLevelPublicKey);
  }

  exportPublicKey(publicKey: VirgilPublicKey) {
    this.throwIfDisposed();
    const foundation = getFoundationModules();
    const keyProvider = new foundation.KeyProvider();
    keyProvider.random = this.random;
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    const publicKeyData = keyProvider.exportPublicKey(publicKey.lowLevelPublicKey);
    keyProvider.delete();
    return toBuffer(publicKeyData);
  }

  encrypt(data: Data, publicKey: VirgilPublicKey | VirgilPublicKey[], enablePadding?: boolean) {
    this.throwIfDisposed();
    const myData = dataToUint8Array(data, 'utf8');
    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);
    const foundation = getFoundationModules();
    const recipientCipher = new foundation.RecipientCipher();
    const aes256Gcm = new foundation.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;
    let randomPadding: FoundationModules.RandomPadding | undefined;
    let paddingParams: FoundationModules.PaddingParams | undefined;
    if (enablePadding) {
      randomPadding = new foundation.RandomPadding();
      randomPadding.random = this.random;
      recipientCipher.encryptionPadding = randomPadding;
      paddingParams = foundation.PaddingParams.newWithConstraints(
        VirgilCrypto.PADDING_LEN,
        VirgilCrypto.PADDING_LEN,
      );
      recipientCipher.paddingParams = paddingParams;
    }
    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, publicKeys[index].lowLevelPublicKey);
    });
    try {
      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();
      return NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
    } finally {
      recipientCipher.delete();
      aes256Gcm.delete();
      if (paddingParams) {
        paddingParams.delete();
      }
      if (randomPadding) {
        randomPadding.delete();
      }
    }
  }

  decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
    this.throwIfDisposed();
    const myData = dataToUint8Array(encryptedData, 'base64');
    validatePrivateKey(privateKey);
    const foundation = getFoundationModules();
    const recipientCipher = new foundation.RecipientCipher();
    recipientCipher.random = this.random;
    const paddingParams = foundation.PaddingParams.newWithConstraints(
      VirgilCrypto.PADDING_LEN,
      VirgilCrypto.PADDING_LEN,
    );
    recipientCipher.paddingParams = paddingParams;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        privateKey.lowLevelPrivateKey,
        new Uint8Array(0),
      );
      const processDecryption = recipientCipher.processDecryption(myData);
      const finishDecryption = recipientCipher.finishDecryption();
      return NodeBuffer.concat([processDecryption, finishDecryption]);
    } finally {
      paddingParams.delete();
      recipientCipher.delete();
    }
  }

  calculateHash(
    data: Data,
    algorithm: HashAlgorithmType[keyof HashAlgorithmType] = HashAlgorithm.SHA512,
  ) {
    const myData = dataToUint8Array(data, 'utf8');
    let result: Uint8Array;
    switch (algorithm) {
      case HashAlgorithm.SHA224:
        result = this.createHash(myData, getFoundationModules().Sha224);
        break;
      case HashAlgorithm.SHA256:
        result = this.createHash(myData, getFoundationModules().Sha256);
        break;
      case HashAlgorithm.SHA384:
        result = this.createHash(myData, getFoundationModules().Sha384);
        break;
      case HashAlgorithm.SHA512:
        result = this.createHash(myData, getFoundationModules().Sha512);
        break;
      default:
        throw new TypeError('Unknown hash algorithm');
    }
    return toBuffer(result);
  }

  extractPublicKey(privateKey: VirgilPrivateKey) {
    this.throwIfDisposed();
    validatePrivateKey(privateKey);
    const lowLevelPublicKey = privateKey.lowLevelPrivateKey.extractPublicKey();
    return new VirgilPublicKey(privateKey.identifier, lowLevelPublicKey);
  }

  calculateSignature(data: Data, privateKey: VirgilPrivateKey) {
    this.throwIfDisposed();

    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const foundation = getFoundationModules();

    const signer = new foundation.Signer();
    const sha512 = new foundation.Sha512();
    signer.random = this.random;
    signer.hash = sha512;

    signer.reset();
    signer.appendData(myData);
    try {
      const signature = signer.sign(privateKey.lowLevelPrivateKey);
      return toBuffer(signature);
    } finally {
      signer.delete();
      sha512.delete();
    }
  }

  verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
    this.throwIfDisposed();

    const myData = dataToUint8Array(data, 'utf8');
    const mySignature = dataToUint8Array(signature, 'base64');

    validatePublicKey(publicKey);

    const foundation = getFoundationModules();

    const verifier = new foundation.Verifier();
    try {
      verifier.reset(mySignature);
    } catch (error) {
      verifier.delete();
      throw error;
    }
    verifier.appendData(myData);

    const result = verifier.verify(publicKey.lowLevelPublicKey);

    verifier.delete();

    return result;
  }

  signAndEncrypt(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
    enablePadding?: boolean,
  ) {
    this.throwIfDisposed();
    const myData = dataToUint8Array(data, 'utf8');
    validatePrivateKey(privateKey);
    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);
    const foundation = getFoundationModules();
    const recipientCipher = new foundation.RecipientCipher();
    const aes256Gcm = new foundation.Aes256Gcm();
    const sha512 = new foundation.Sha512();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;
    recipientCipher.signerHash = sha512;
    let randomPadding: FoundationModules.RandomPadding | undefined;
    let paddingParams: FoundationModules.PaddingParams | undefined;
    if (enablePadding) {
      randomPadding = new foundation.RandomPadding();
      randomPadding.random = this.random;
      recipientCipher.encryptionPadding = randomPadding;
      paddingParams = foundation.PaddingParams.newWithConstraints(
        VirgilCrypto.PADDING_LEN,
        VirgilCrypto.PADDING_LEN,
      );
      recipientCipher.paddingParams = paddingParams;
    }
    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, publicKeys[index].lowLevelPublicKey);
    });
    try {
      recipientCipher.addSigner(privateKey.identifier, privateKey.lowLevelPrivateKey);
      recipientCipher.startSignedEncryption(myData.length);
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();
      const messageInfoFooter = recipientCipher.packMessageInfoFooter();
      return NodeBuffer.concat([
        messageInfo,
        processEncryption,
        finishEncryption,
        messageInfoFooter,
      ]);
    } finally {
      sha512.delete();
      aes256Gcm.delete();
      if (randomPadding) {
        randomPadding.delete();
      }
      if (paddingParams) {
        paddingParams.delete();
      }
      recipientCipher.delete();
    }
  }

  signThenEncrypt(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
    enablePadding?: boolean,
  ) {
    this.throwIfDisposed();

    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const foundation = getFoundationModules();

    const recipientCipher = new foundation.RecipientCipher();
    const aes256Gcm = new foundation.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;
    let randomPadding: FoundationModules.RandomPadding | undefined;
    let paddingParams: FoundationModules.PaddingParams | undefined;
    if (enablePadding) {
      randomPadding = new foundation.RandomPadding();
      randomPadding.random = this.random;
      recipientCipher.encryptionPadding = randomPadding;
      paddingParams = foundation.PaddingParams.newWithConstraints(
        VirgilCrypto.PADDING_LEN,
        VirgilCrypto.PADDING_LEN,
      );
      recipientCipher.paddingParams = paddingParams;
    }

    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, publicKeys[index].lowLevelPublicKey);
    });

    const messageInfoCustomParams = recipientCipher.customParams();

    try {
      const signature = this.calculateSignature(myData, privateKey);

      messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, signature);
      messageInfoCustomParams.addData(DATA_SIGNER_ID_KEY, privateKey.identifier);

      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();
      return NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
    } finally {
      if (randomPadding) {
        randomPadding.delete();
      }
      if (paddingParams) {
        paddingParams.delete();
      }
      recipientCipher.delete();
      aes256Gcm.delete();
      messageInfoCustomParams.delete();
    }
  }

  decryptAndVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    this.throwIfDisposed();
    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');
    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);
    validatePrivateKey(privateKey);
    const foundation = getFoundationModules();
    const paddingParams = foundation.PaddingParams.newWithConstraints(
      VirgilCrypto.PADDING_LEN,
      VirgilCrypto.PADDING_LEN,
    );
    const recipientCipher = new foundation.RecipientCipher();
    recipientCipher.random = this.random;
    recipientCipher.paddingParams = paddingParams;
    let decryptedData: BufferType;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        privateKey.lowLevelPrivateKey,
        new Uint8Array(0),
      );
      const processDecryption = recipientCipher.processDecryption(myEncryptedData);
      const finishDecryption = recipientCipher.finishDecryption();
      decryptedData = NodeBuffer.concat([processDecryption, finishDecryption]);
    } catch (error) {
      paddingParams.delete();
      recipientCipher.delete();
      throw error;
    }
    if (!recipientCipher.isDataSigned()) {
      paddingParams.delete();
      recipientCipher.delete();
      throw new Error('Data is not signed');
    }
    const signerInfoList = recipientCipher.signerInfos();
    if (!signerInfoList.hasItem()) {
      paddingParams.delete();
      signerInfoList.delete();
      recipientCipher.delete();
      throw new Error('Data is not signed');
    }
    const signerInfo = signerInfoList.item();
    let signerPublicKey: VirgilPublicKey;
    for (let i = 0; i < publicKeys.length; i += 1) {
      if (NodeBuffer.compare(signerInfo.signerId(), publicKeys[i].identifier) === 0) {
        signerPublicKey = publicKeys[i];
        break;
      }
      if (i === publicKeys.length - 1) {
        paddingParams.delete();
        signerInfo.delete();
        signerInfoList.delete();
        recipientCipher.delete();
        throw new Error('Signer not found');
      }
    }
    if (!recipientCipher.verifySignerInfo(signerInfo, signerPublicKey!.lowLevelPublicKey)) {
      paddingParams.delete();
      signerInfo.delete();
      signerInfoList.delete();
      recipientCipher.delete();
      throw new Error('Invalid signature');
    }
    paddingParams.delete();
    signerInfo.delete();
    signerInfoList.delete();
    recipientCipher.delete();
    return decryptedData;
  }

  decryptThenVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    this.throwIfDisposed();

    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    validatePrivateKey(privateKey);

    const foundation = getFoundationModules();

    const paddingParams = foundation.PaddingParams.newWithConstraints(
      VirgilCrypto.PADDING_LEN,
      VirgilCrypto.PADDING_LEN,
    );
    const recipientCipher = new foundation.RecipientCipher();
    recipientCipher.random = this.random;
    recipientCipher.paddingParams = paddingParams;

    let decryptedData: BufferType;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        privateKey.lowLevelPrivateKey,
        new Uint8Array(0),
      );
      const processDecryption = recipientCipher.processDecryption(myEncryptedData);
      const finishDecryption = recipientCipher.finishDecryption();
      decryptedData = NodeBuffer.concat([processDecryption, finishDecryption]);
    } catch (error) {
      paddingParams.delete();
      recipientCipher.delete();
      throw error;
    }

    const messageInfoCustomParams = recipientCipher.customParams();

    let signerPublicKey: VirgilPublicKey | undefined;
    if (publicKeys.length === 1) {
      signerPublicKey = publicKeys[0];
    } else {
      let signerId: Uint8Array;
      try {
        signerId = messageInfoCustomParams.findData(DATA_SIGNER_ID_KEY);
      } catch (error) {
        paddingParams.delete();
        recipientCipher.delete();
        messageInfoCustomParams.delete();
        throw error;
      }
      for (let i = 0; i < publicKeys.length; i += 1) {
        if (NodeBuffer.compare(signerId, publicKeys[i].identifier) === 0) {
          signerPublicKey = publicKeys[i];
          break;
        }
      }
      if (!signerPublicKey) {
        paddingParams.delete();
        recipientCipher.delete();
        messageInfoCustomParams.delete();
        throw new Error('Signer not found');
      }
    }

    try {
      const signature = messageInfoCustomParams.findData(DATA_SIGNATURE_KEY);
      const isValid = this.verifySignature(decryptedData, signature, signerPublicKey);
      if (!isValid) {
        throw new Error('Invalid signature');
      }
      return decryptedData;
    } finally {
      paddingParams.delete();
      recipientCipher.delete();
      messageInfoCustomParams.delete();
    }
  }

  getRandomBytes(length: number) {
    this.throwIfDisposed();
    const bytes = this.random.random(length);
    return toBuffer(bytes);
  }

  signThenEncryptDetached(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
    enablePadding?: boolean,
  ) {
    this.throwIfDisposed();

    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const foundation = getFoundationModules();

    const recipientCipher = new foundation.RecipientCipher();
    const aes256Gcm = new foundation.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;
    let randomPadding: FoundationModules.RandomPadding | undefined;
    let paddingParams: FoundationModules.PaddingParams | undefined;
    if (enablePadding) {
      randomPadding = new foundation.RandomPadding();
      randomPadding.random = this.random;
      recipientCipher.encryptionPadding = randomPadding;
      paddingParams = foundation.PaddingParams.newWithConstraints(
        VirgilCrypto.PADDING_LEN,
        VirgilCrypto.PADDING_LEN,
      );
      recipientCipher.paddingParams = paddingParams;
    }

    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, publicKeys[index].lowLevelPublicKey);
    });

    const messageInfoCustomParams = recipientCipher.customParams();

    try {
      const signature = this.calculateSignature(myData, privateKey);

      messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, signature);
      messageInfoCustomParams.addData(DATA_SIGNER_ID_KEY, privateKey.identifier);

      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();
      const encryptedData = NodeBuffer.concat([processEncryption, finishEncryption]);
      const metadata = toBuffer(messageInfo);
      return { encryptedData, metadata };
    } finally {
      if (randomPadding) {
        randomPadding.delete();
      }
      if (paddingParams) {
        paddingParams.delete();
      }
      recipientCipher.delete();
      aes256Gcm.delete();
      messageInfoCustomParams.delete();
    }
  }

  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    this.throwIfDisposed();

    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');
    const myMetadata = dataToUint8Array(metadata, 'base64');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const foundation = getFoundationModules();

    const paddingParams = foundation.PaddingParams.newWithConstraints(
      VirgilCrypto.PADDING_LEN,
      VirgilCrypto.PADDING_LEN,
    );
    const recipientCipher = new foundation.RecipientCipher();
    recipientCipher.random = this.random;
    recipientCipher.paddingParams = paddingParams;

    let decryptedData: BufferType;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        privateKey.lowLevelPrivateKey,
        myMetadata,
      );
      const processDecryption = recipientCipher.processDecryption(myEncryptedData);
      const finishDecryption = recipientCipher.finishDecryption();
      decryptedData = NodeBuffer.concat([processDecryption, finishDecryption]);
    } catch (error) {
      paddingParams.delete();
      recipientCipher.delete();
      throw error;
    }

    const messageInfoCustomParams = recipientCipher.customParams();

    let signerPublicKey: VirgilPublicKey | undefined;
    if (publicKeys.length === 1) {
      signerPublicKey = publicKeys[0];
    } else {
      let signerId: Uint8Array;
      try {
        signerId = messageInfoCustomParams.findData(DATA_SIGNER_ID_KEY);
      } catch (error) {
        paddingParams.delete();
        recipientCipher.delete();
        messageInfoCustomParams.delete();
        throw error;
      }
      for (let i = 0; i < publicKeys.length; i += 1) {
        if (NodeBuffer.compare(signerId, publicKeys[i].identifier) === 0) {
          signerPublicKey = publicKeys[i];
          break;
        }
      }
      if (!signerPublicKey) {
        paddingParams.delete();
        recipientCipher.delete();
        messageInfoCustomParams.delete();
        throw new Error('Signer not found');
      }
    }

    try {
      const signature = messageInfoCustomParams.findData(DATA_SIGNATURE_KEY);
      const isValid = this.verifySignature(decryptedData, signature, signerPublicKey);
      if (!isValid) {
        throw new Error('Invalid signature');
      }
      return decryptedData;
    } finally {
      paddingParams.delete();
      recipientCipher.delete();
      messageInfoCustomParams.delete();
    }
  }

  createStreamCipher(publicKey: VirgilPublicKey | VirgilPublicKey[], signature?: Data) {
    this.throwIfDisposed();
    return new VirgilStreamCipher(publicKey, signature);
  }

  createStreamDecipher(privateKey: VirgilPrivateKey) {
    this.throwIfDisposed();
    return new VirgilStreamDecipher(privateKey);
  }

  createStreamSigner() {
    this.throwIfDisposed();
    return new VirgilStreamSigner();
  }

  createStreamVerifier(signature: Data) {
    this.throwIfDisposed();
    return new VirgilStreamVerifier(signature);
  }

  generateGroupSession(groupId: Data): IGroupSession {
    this.throwIfDisposed();

    const groupIdBytes = dataToUint8Array(groupId, 'utf8');
    this.validateGroupId(groupIdBytes);
    const sessionId = computeSessionId(groupIdBytes);
    const initialEpoch = createInitialEpoch(sessionId);

    const initialEpochMessage = initialEpoch.serialize();
    initialEpoch.delete();
    return createVirgilGroupSession([initialEpochMessage]);
  }

  importGroupSession(epochMessages: Data[]): IGroupSession {
    this.throwIfDisposed();

    if (!Array.isArray(epochMessages)) {
      throw new TypeError('Epoch messages must be an array.');
    }

    if (epochMessages.length === 0) {
      throw new Error('Epoch messages must not be empty.');
    }

    return createVirgilGroupSession(epochMessages.map(it => dataToUint8Array(it, 'base64')));
  }

  calculateGroupSessionId(groupId: Data) {
    this.throwIfDisposed();
    const groupIdBytes = dataToUint8Array(groupId, 'utf8');
    this.validateGroupId(groupIdBytes);
    return toBuffer(computeSessionId(groupIdBytes)).toString('hex');
  }

  private validateGroupId(groupId: Uint8Array) {
    if (groupId.byteLength < MIN_GROUP_ID_BYTE_LENGTH) {
      throw new Error(
        `The given group Id is too short. Must be at least ${MIN_GROUP_ID_BYTE_LENGTH} bytes.`,
      );
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private createHash(data: Uint8Array, HashClass: any) {
    const hashInstance = new HashClass();
    const hash = hashInstance.hash(data);
    hashInstance.delete();
    return hash;
  }

  private calculateKeyPairIdentifier(serializedPublicKey: Uint8Array) {
    if (this.useSha256Identifiers) {
      return this.createHash(serializedPublicKey, getFoundationModules().Sha256);
    }
    return this.createHash(serializedPublicKey, getFoundationModules().Sha512).slice(0, 8);
  }

  private generateKeyPair(
    keyProvider: FoundationModules.KeyProvider,
    keyPairTypeConfig: KeyPairTypeConfig,
  ) {
    let lowLevelPrivateKey: FoundationModules.PrivateKey;
    if (isCompoundKeyPairType(keyPairTypeConfig.type)) {
      const [cipherFirstKeyAlgId, cipherSecondKeyAlgId] = keyPairTypeConfig.cipherAlgIds!;
      const [signerFirstKeyAlgId, signerSecondKeyAlgId] = keyPairTypeConfig.signerAlgIds!;
      lowLevelPrivateKey = keyProvider.generateCompoundHybridPrivateKey(
        cipherFirstKeyAlgId,
        cipherSecondKeyAlgId,
        signerFirstKeyAlgId,
        signerSecondKeyAlgId,
      );
    } else {
      if (isRSAKeyPairType(keyPairTypeConfig.type)) {
        keyProvider.setRsaParams(keyPairTypeConfig.bitlen!);
      }
      lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairTypeConfig.algId!);
    }
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();
    let serializedPublicKey: Uint8Array;
    try {
      serializedPublicKey = keyProvider.exportPublicKey(lowLevelPublicKey);
    } catch (error) {
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
      throw error;
    }
    const identifier = this.calculateKeyPairIdentifier(serializedPublicKey);
    return {
      privateKey: new VirgilPrivateKey(identifier, lowLevelPrivateKey),
      publicKey: new VirgilPublicKey(identifier, lowLevelPublicKey),
    };
  }

  private throwIfDisposed() {
    if (this._isDisposed) {
      throw new Error(
        'Cannot use an instance of `VirgilCrypto` class after the `dispose` method has been called.',
      );
    }
  }
}
