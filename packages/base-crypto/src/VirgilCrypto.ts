import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { HashAlgorithm, HashAlgorithmType } from './HashAlgorithm';
import { KeyPairType, KeyPairTypeType } from './KeyPairType';
import { ICrypto, NodeBuffer as BufferType, Data, IGroupSession } from './types';
import { toArray } from './utils';
import { validatePrivateKey, validatePublicKey, validatePublicKeysArray } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';
import { VirgilStreamCipher } from './VirgilStreamCipher';
import { VirgilStreamDecipher } from './VirgilStreamDecipher';
import { VirgilStreamSigner } from './VirgilStreamSigner';
import { VirgilStreamVerifier } from './VirgilStreamVerifier';
import { computeSessionId, createInitialEpoch } from './groups/helpers';
import { createVirgilGroupSession } from './groups/createVirgilGroupSession';

export const MIN_GROUP_ID_BYTE_LENGTH = 10;

export interface VirgilCryptoOptions {
  useSha256Identifiers?: boolean;
  defaultKeyPairType?: KeyPairTypeType[keyof KeyPairTypeType];
}

export class VirgilCrypto implements ICrypto {
  readonly useSha256Identifiers: boolean;
  readonly defaultKeyPairType: KeyPairTypeType[keyof KeyPairTypeType];

  readonly hashAlgorithm = HashAlgorithm;
  readonly keyPairType = KeyPairType;

  private readonly foundationModules: typeof FoundationModules;
  private readonly keyAsn1Serializer: FoundationModules.KeyAsn1Serializer;
  private readonly random: FoundationModules.CtrDrbg;
  private _isDisposed: boolean;

  get isDisposed() {
    return this._isDisposed;
  }

  constructor(options: VirgilCryptoOptions = {}) {
    this.foundationModules = getFoundationModules();

    this.keyAsn1Serializer = new this.foundationModules.KeyAsn1Serializer();
    try {
      this.keyAsn1Serializer.setupDefaults();
    } catch (error) {
      this.keyAsn1Serializer.delete();
      throw error;
    }

    this.random = new this.foundationModules.CtrDrbg();
    try {
      this.random.setupDefaults();
    } catch (error) {
      this.keyAsn1Serializer.delete();
      this.random.delete();
      throw error;
    }

    this.defaultKeyPairType = options.defaultKeyPairType || KeyPairType.Default;
    this.useSha256Identifiers = options.useSha256Identifiers || false;
    this._isDisposed = false;
  }

  dispose() {
    this.keyAsn1Serializer.delete();
    this.random.delete();
    this._isDisposed = true;
  }

  generateKeys(type?: KeyPairTypeType[keyof KeyPairTypeType]) {
    this.throwUnlessDisposed();

    const keyPairType = type ? type : this.defaultKeyPairType;

    const keyProvider = new this.foundationModules.KeyProvider();
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    if (keyPairType.algId === this.foundationModules.AlgId.RSA) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      keyProvider.setRsaParams(keyPairType.bitlen!);
    }

    let lowLevelPrivateKey: FoundationModules.PrivateKey;
    try {
      lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    try {
      const serializedPublicKey = this.keyAsn1Serializer.serializePublicKey(lowLevelPublicKey);
      const identifier = this.calculateKeypairIdentifier(
        serializedPublicKey,
        this.useSha256Identifiers,
      );
      return {
        privateKey: new VirgilPrivateKey(identifier, lowLevelPrivateKey),
        publicKey: new VirgilPublicKey(identifier, lowLevelPublicKey),
      };
    } finally {
      keyProvider.delete();
    }
  }

  generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairTypeType[keyof KeyPairTypeType]) {
    this.throwUnlessDisposed();

    const keyPairType = type ? type : this.defaultKeyPairType;
    const myKeyMaterial = dataToUint8Array(keyMaterial, 'base64');

    const keyMaterialRng = new this.foundationModules.KeyMaterialRng();
    keyMaterialRng.resetKeyMaterial(myKeyMaterial);

    const keyProvider = new this.foundationModules.KeyProvider();
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyMaterialRng.delete();
      keyProvider.delete();
      throw error;
    }
    keyProvider.random = keyMaterialRng;
    if (keyPairType.algId === this.foundationModules.AlgId.RSA) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      keyProvider.setRsaParams(keyPairType.bitlen!);
    }

    let lowLevelPrivateKey: FoundationModules.PrivateKey;
    try {
      lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
    } catch (error) {
      keyMaterialRng.delete();
      keyProvider.delete();
      throw error;
    }
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    try {
      const serializedPublicKey = this.keyAsn1Serializer.serializePublicKey(lowLevelPublicKey);
      const identifier = this.calculateKeypairIdentifier(
        serializedPublicKey,
        this.useSha256Identifiers,
      );
      return {
        privateKey: new VirgilPrivateKey(identifier, lowLevelPrivateKey),
        publicKey: new VirgilPublicKey(identifier, lowLevelPublicKey),
      };
    } finally {
      keyMaterialRng.delete();
      keyProvider.delete();
    }
  }

  importPrivateKey(rawPrivateKey: Data) {
    this.throwUnlessDisposed();

    const serializedPrivateKey = dataToUint8Array(rawPrivateKey, 'base64');

    const keyProvider = new this.foundationModules.KeyProvider();
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }

    const lowLevelPrivateKey = keyProvider.importPrivateKey(serializedPrivateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    try {
      const serializedPublicKey = this.keyAsn1Serializer.serializePublicKey(lowLevelPublicKey);
      const identifier = this.calculateKeypairIdentifier(
        serializedPublicKey,
        this.useSha256Identifiers,
      );
      return new VirgilPrivateKey(identifier, lowLevelPrivateKey);
    } finally {
      lowLevelPublicKey.delete();
      keyProvider.delete();
    }
  }

  exportPrivateKey(privateKey: VirgilPrivateKey) {
    this.throwUnlessDisposed();
    validatePrivateKey(privateKey);
    return toBuffer(this.keyAsn1Serializer.serializePrivateKey(privateKey.lowLevelPrivateKey));
  }

  importPublicKey(rawPublicKey: Data) {
    this.throwUnlessDisposed();

    const serializedPublicKey = dataToUint8Array(rawPublicKey, 'base64');

    const keyProvider = new this.foundationModules.KeyProvider();
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyProvider.delete();
      throw error;
    }

    const lowLevelPublicKey = keyProvider.importPublicKey(serializedPublicKey);
    const identifier = this.calculateKeypairIdentifier(
      serializedPublicKey,
      this.useSha256Identifiers,
    );

    keyProvider.delete();

    return new VirgilPublicKey(identifier, lowLevelPublicKey);
  }

  exportPublicKey(publicKey: VirgilPublicKey) {
    this.throwUnlessDisposed();
    return toBuffer(this.keyAsn1Serializer.serializePublicKey(publicKey.lowLevelPublicKey));
  }

  encrypt(data: Data, publicKey: VirgilPublicKey | VirgilPublicKey[]) {
    this.throwUnlessDisposed();

    const myData = dataToUint8Array(data, 'utf8');

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

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
    }
  }

  decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
    this.throwUnlessDisposed();

    const myData = dataToUint8Array(encryptedData, 'base64');

    validatePrivateKey(privateKey);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

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
    this.throwUnlessDisposed();
    validatePrivateKey(privateKey);
    const lowLevelPublicKey = privateKey.lowLevelPrivateKey.extractPublicKey();
    return new VirgilPublicKey(privateKey.identifier, lowLevelPublicKey);
  }

  calculateSignature(data: Data, privateKey: VirgilPrivateKey) {
    this.throwUnlessDisposed();

    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const signer = new this.foundationModules.Signer();
    const sha512 = new this.foundationModules.Sha512();
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
    this.throwUnlessDisposed();

    const myData = dataToUint8Array(data, 'utf8');
    const mySignature = dataToUint8Array(signature, 'base64');

    validatePublicKey(publicKey);

    const verifier = new this.foundationModules.Verifier();
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

  signThenEncrypt(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    this.throwUnlessDisposed();

    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

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
      recipientCipher.delete();
      aes256Gcm.delete();
      messageInfoCustomParams.delete();
    }
  }

  decryptThenVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    this.throwUnlessDisposed();

    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    validatePrivateKey(privateKey);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

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
      recipientCipher.delete();
      messageInfoCustomParams.delete();
    }
  }

  getRandomBytes(length: number) {
    this.throwUnlessDisposed();
    const bytes = this.random.random(length);
    return toBuffer(bytes);
  }

  signThenEncryptDetached(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey | VirgilPublicKey[],
  ) {
    this.throwUnlessDisposed();

    const myData = dataToUint8Array(data, 'utf8');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

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
    this.throwUnlessDisposed();

    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');
    const myMetadata = dataToUint8Array(metadata, 'base64');

    validatePrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

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
      recipientCipher.delete();
      messageInfoCustomParams.delete();
    }
  }

  createStreamCipher(publicKey: VirgilPublicKey | VirgilPublicKey[], signature?: Data) {
    this.throwUnlessDisposed();
    return new VirgilStreamCipher(publicKey, signature);
  }

  createStreamDecipher(privateKey: VirgilPrivateKey) {
    this.throwUnlessDisposed();
    return new VirgilStreamDecipher(privateKey);
  }

  createStreamSigner() {
    this.throwUnlessDisposed();
    return new VirgilStreamSigner();
  }

  createStreamVerifier(signature: Data) {
    this.throwUnlessDisposed();
    return new VirgilStreamVerifier(signature);
  }

  generateGroupSession(groupId: Data): IGroupSession {
    this.throwUnlessDisposed();

    const groupIdBytes = dataToUint8Array(groupId, 'utf8');
    this.validateGroupId(groupIdBytes);
    const sessionId = computeSessionId(groupIdBytes);
    const initialEpoch = createInitialEpoch(sessionId);

    const initialEpochMessage = initialEpoch.serialize();
    initialEpoch.delete();
    return createVirgilGroupSession([initialEpochMessage]);
  }

  importGroupSession(epochMessages: Data[]): IGroupSession {
    this.throwUnlessDisposed();

    if (!Array.isArray(epochMessages)) {
      throw new TypeError('Epoch messages must be an array.');
    }

    if (epochMessages.length === 0) {
      throw new Error('Epoch messages must not be empty.');
    }

    return createVirgilGroupSession(epochMessages.map(it => dataToUint8Array(it, 'base64')));
  }

  calculateGroupSessionId(groupId: Data) {
    this.throwUnlessDisposed();
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

  private calculateKeypairIdentifier(
    serializedPublicKey: Uint8Array,
    useSha256Identifiers: boolean,
  ) {
    if (useSha256Identifiers) {
      return this.createHash(serializedPublicKey, this.foundationModules.Sha256);
    }
    return this.createHash(serializedPublicKey, this.foundationModules.Sha512).slice(0, 8);
  }

  private throwUnlessDisposed() {
    if (this._isDisposed) {
      throw new Error(
        'Cannot use an instance of `VirgilCrypto` class after the `dispose` method has been called.',
      );
    }
  }
}
