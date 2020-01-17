import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { createVirgilGroupSession } from './groups/createVirgilGroupSession';
import { computeSessionId, createInitialEpoch } from './groups/helpers';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { getRandom, getKeyProvider } from './globalInstances';
import { HashAlgorithm } from './HashAlgorithm';
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

export interface VirgilCryptoOptions {
  useSha256Identifiers?: boolean;
  defaultKeyPairType?: KeyPairType;
}

export class VirgilCrypto implements ICrypto {
  static get PADDING_LEN() {
    return 160;
  }

  static get MIN_GROUP_ID_BYTE_LENGTH() {
    return 10;
  }

  readonly hashAlgorithm = HashAlgorithm;
  readonly keyPairType = KeyPairType;

  readonly useSha256Identifiers: boolean;
  readonly defaultKeyPairType: KeyPairType;

  constructor(options: VirgilCryptoOptions = {}) {
    this.defaultKeyPairType = options.defaultKeyPairType || KeyPairType.DEFAULT;
    this.useSha256Identifiers = options.useSha256Identifiers || false;
  }

  generateKeys(type?: KeyPairType[keyof KeyPairType]) {
    const keyPairType = type ? type : this.defaultKeyPairType;
    const keyPairTypeConfig = getKeyPairTypeConfig(keyPairType);
    return this.generateKeyPair(getKeyProvider(), keyPairTypeConfig);
  }

  generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairType[keyof KeyPairType]) {
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
    const keyProvider = getKeyProvider();
    const serializedPrivateKey = dataToUint8Array(rawPrivateKey, 'base64');
    const lowLevelPrivateKey = keyProvider.importPrivateKey(serializedPrivateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();
    try {
      const serializedPublicKey = keyProvider.exportPublicKey(lowLevelPublicKey);
      const identifier = this.calculateKeyPairIdentifier(serializedPublicKey);
      return new VirgilPrivateKey(identifier, lowLevelPrivateKey);
    } finally {
      lowLevelPublicKey.delete();
    }
  }

  exportPrivateKey(privateKey: VirgilPrivateKey) {
    validatePrivateKey(privateKey);
    const keyProvider = getKeyProvider();
    const publicKeyData = keyProvider.exportPrivateKey(privateKey.lowLevelPrivateKey);
    return toBuffer(publicKeyData);
  }

  importPublicKey(rawPublicKey: Data) {
    const serializedPublicKey = dataToUint8Array(rawPublicKey, 'base64');
    const keyProvider = getKeyProvider();
    const lowLevelPublicKey = keyProvider.importPublicKey(serializedPublicKey);
    const identifier = this.calculateKeyPairIdentifier(serializedPublicKey);
    return new VirgilPublicKey(identifier, lowLevelPublicKey);
  }

  exportPublicKey(publicKey: VirgilPublicKey) {
    const keyProvider = getKeyProvider();
    const publicKeyData = keyProvider.exportPublicKey(publicKey.lowLevelPublicKey);
    return toBuffer(publicKeyData);
  }

  encrypt(data: Data, publicKey: VirgilPublicKey, enablePadding?: boolean): BufferType;
  encrypt(data: Data, publicKeys: VirgilPublicKey[], enablePadding?: boolean): BufferType;
  encrypt(arg0: Data, arg1: VirgilPublicKey | VirgilPublicKey[], arg2?: boolean) {
    const data = dataToUint8Array(arg0, 'utf8');
    const publicKeys = toArray(arg1);
    validatePublicKeysArray(publicKeys);
    const foundation = getFoundationModules();
    const random = getRandom();
    const recipientCipher = new foundation.RecipientCipher();
    const aes256Gcm = new foundation.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = random;
    let randomPadding: FoundationModules.RandomPadding | undefined;
    let paddingParams: FoundationModules.PaddingParams | undefined;
    if (arg2) {
      randomPadding = new foundation.RandomPadding();
      randomPadding.random = random;
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
      const processEncryption = recipientCipher.processEncryption(data);
      const finishEncryption = recipientCipher.finishEncryption();
      return NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
    } finally {
      aes256Gcm.delete();
      if (paddingParams) {
        paddingParams.delete();
      }
      if (randomPadding) {
        randomPadding.delete();
      }
      recipientCipher.delete();
    }
  }

  decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
    const myData = dataToUint8Array(encryptedData, 'base64');
    validatePrivateKey(privateKey);
    const foundation = getFoundationModules();
    const recipientCipher = new foundation.RecipientCipher();
    recipientCipher.random = getRandom();
    const paddingParams = foundation.PaddingParams.newWithConstraints(
      VirgilCrypto.PADDING_LEN,
      VirgilCrypto.PADDING_LEN,
    );
    recipientCipher.paddingParams = paddingParams;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        privateKey.lowLevelPrivateKey,
        new Uint8Array(),
      );
      const processDecryption = recipientCipher.processDecryption(myData);
      const finishDecryption = recipientCipher.finishDecryption();
      return NodeBuffer.concat([processDecryption, finishDecryption]);
    } finally {
      paddingParams.delete();
      recipientCipher.delete();
    }
  }

  calculateHash(data: Data, algorithm: HashAlgorithm[keyof HashAlgorithm] = HashAlgorithm.SHA512) {
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
    validatePrivateKey(privateKey);
    const lowLevelPublicKey = privateKey.lowLevelPrivateKey.extractPublicKey();
    return new VirgilPublicKey(privateKey.identifier, lowLevelPublicKey);
  }

  calculateSignature(data: Data, privateKey: VirgilPrivateKey) {
    const myData = dataToUint8Array(data, 'utf8');
    validatePrivateKey(privateKey);
    const foundation = getFoundationModules();
    const signer = new foundation.Signer();
    const sha512 = new foundation.Sha512();
    signer.random = getRandom();
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
    publicKey: VirgilPublicKey,
    enablePadding?: boolean,
  ): BufferType;
  signAndEncrypt(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
    enablePadding?: boolean,
  ): BufferType;
  signAndEncrypt(
    arg0: Data,
    arg1: VirgilPrivateKey,
    arg2: VirgilPublicKey | VirgilPublicKey[],
    arg3?: boolean,
  ) {
    const data = dataToUint8Array(arg0, 'utf8');
    validatePrivateKey(arg1);
    const publicKeys = toArray(arg2);
    validatePublicKeysArray(publicKeys);
    const {
      messageInfo,
      processEncryption,
      finishEncryption,
      messageInfoFooter,
    } = this._signAndEncrypt(data, arg1, publicKeys, arg3);
    return NodeBuffer.concat([messageInfo, processEncryption, finishEncryption, messageInfoFooter]);
  }

  signThenEncrypt(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey,
    enablePadding?: boolean,
  ): BufferType;
  signThenEncrypt(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
    enablePadding?: boolean,
  ): BufferType;
  signThenEncrypt(
    arg0: Data,
    arg1: VirgilPrivateKey,
    arg2: VirgilPublicKey | VirgilPublicKey[],
    arg3?: boolean,
  ) {
    const data = dataToUint8Array(arg0, 'utf8');
    validatePrivateKey(arg1);
    const publicKeys = toArray(arg2);
    validatePublicKeysArray(publicKeys);
    const { messageInfo, processEncryption, finishEncryption } = this._signThenEncrypt(
      data,
      arg1,
      publicKeys,
      arg3,
    );
    return NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
  }

  decryptAndVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey,
  ): BufferType;
  decryptAndVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
  ): BufferType;
  decryptAndVerify(arg0: Data, arg1: VirgilPrivateKey, arg2: VirgilPublicKey | VirgilPublicKey[]) {
    const encryptedData = dataToUint8Array(arg0, 'base64');
    validatePrivateKey(arg1);
    const publicKeys = toArray(arg2);
    validatePublicKeysArray(publicKeys);
    return this._decryptAndVerify(encryptedData, new Uint8Array(), arg1, publicKeys);
  }

  decryptThenVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey,
  ): BufferType;
  decryptThenVerify(
    encryptedData: Data,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
  ): BufferType;
  decryptThenVerify(arg0: Data, arg1: VirgilPrivateKey, arg2: VirgilPublicKey | VirgilPublicKey[]) {
    const encryptedData = dataToUint8Array(arg0, 'base64');
    validatePrivateKey(arg1);
    const publicKeys = toArray(arg2);
    validatePublicKeysArray(publicKeys);
    return this._decryptThenVerify(encryptedData, new Uint8Array(), arg1, publicKeys);
  }

  getRandomBytes(length: number) {
    const bytes = getRandom().random(length);
    return toBuffer(bytes);
  }

  signThenEncryptDetached(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey,
    enablePadding?: boolean,
  ): { encryptedData: BufferType; metadata: BufferType };
  signThenEncryptDetached(
    data: Data,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
    enablePadding?: boolean,
  ): { encryptedData: BufferType; metadata: BufferType };
  signThenEncryptDetached(
    arg0: Data,
    arg1: VirgilPrivateKey,
    arg2: VirgilPublicKey | VirgilPublicKey[],
    arg3?: boolean,
  ) {
    const data = dataToUint8Array(arg0, 'utf8');
    validatePrivateKey(arg1);
    const publicKeys = toArray(arg2);
    validatePublicKeysArray(publicKeys);
    const { messageInfo, processEncryption, finishEncryption } = this._signThenEncrypt(
      data,
      arg1,
      publicKeys,
      arg3,
    );
    return {
      encryptedData: NodeBuffer.concat([processEncryption, finishEncryption]),
      metadata: toBuffer(messageInfo),
    };
  }

  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: VirgilPrivateKey,
    publicKey: VirgilPublicKey,
  ): BufferType;
  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
  ): BufferType;
  decryptThenVerifyDetached(
    arg0: Data,
    arg1: Data,
    arg2: VirgilPrivateKey,
    arg3: VirgilPublicKey | VirgilPublicKey[],
  ) {
    const encryptedData = dataToUint8Array(arg0, 'base64');
    const messageInfo = dataToUint8Array(arg1, 'base64');
    validatePrivateKey(arg2);
    const publicKeys = toArray(arg3);
    validatePublicKeysArray(publicKeys);
    return this._decryptThenVerify(encryptedData, messageInfo, arg2, publicKeys);
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

  generateGroupSession(groupId: Data): IGroupSession {
    const groupIdBytes = dataToUint8Array(groupId, 'utf8');
    this.validateGroupId(groupIdBytes);
    const sessionId = computeSessionId(groupIdBytes);
    const initialEpoch = createInitialEpoch(sessionId);
    const initialEpochMessage = initialEpoch.serialize();
    initialEpoch.delete();
    return createVirgilGroupSession([initialEpochMessage]);
  }

  importGroupSession(epochMessages: Data[]): IGroupSession {
    if (!Array.isArray(epochMessages)) {
      throw new TypeError('Epoch messages must be an array.');
    }
    if (epochMessages.length === 0) {
      throw new Error('Epoch messages must not be empty.');
    }
    return createVirgilGroupSession(epochMessages.map(it => dataToUint8Array(it, 'base64')));
  }

  calculateGroupSessionId(groupId: Data) {
    const groupIdBytes = dataToUint8Array(groupId, 'utf8');
    this.validateGroupId(groupIdBytes);
    return toBuffer(computeSessionId(groupIdBytes)).toString('hex');
  }

  private validateGroupId(groupId: Uint8Array) {
    if (groupId.byteLength < VirgilCrypto.MIN_GROUP_ID_BYTE_LENGTH) {
      throw new Error(
        `The given group Id is too short. Must be at least ${VirgilCrypto.MIN_GROUP_ID_BYTE_LENGTH} bytes.`,
      );
    }
  }

  private createHash(
    data: Uint8Array,
    HashClass: { new (): FoundationModules.Hash & FoundationModules.FoundationObject },
  ) {
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

  private _signAndEncrypt(
    data: Uint8Array,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
    enablePadding?: boolean,
  ) {
    const foundation = getFoundationModules();
    const random = getRandom();
    const recipientCipher = new foundation.RecipientCipher();
    const aes256Gcm = new foundation.Aes256Gcm();
    const sha512 = new foundation.Sha512();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = random;
    recipientCipher.signerHash = sha512;
    let randomPadding: FoundationModules.RandomPadding | undefined;
    let paddingParams: FoundationModules.PaddingParams | undefined;
    if (enablePadding) {
      randomPadding = new foundation.RandomPadding();
      randomPadding.random = random;
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
      recipientCipher.startSignedEncryption(data.length);
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(data);
      const finishEncryption = recipientCipher.finishEncryption();
      const messageInfoFooter = recipientCipher.packMessageInfoFooter();
      return {
        messageInfo,
        processEncryption,
        finishEncryption,
        messageInfoFooter,
      };
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

  private _signThenEncrypt(
    data: Uint8Array,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
    enablePadding?: boolean,
  ) {
    const foundation = getFoundationModules();
    const random = getRandom();
    const recipientCipher = new foundation.RecipientCipher();
    const aes256Gcm = new foundation.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = random;
    let randomPadding: FoundationModules.RandomPadding | undefined;
    let paddingParams: FoundationModules.PaddingParams | undefined;
    if (enablePadding) {
      randomPadding = new foundation.RandomPadding();
      randomPadding.random = random;
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
      const signature = this.calculateSignature(data, privateKey);
      messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, signature);
      messageInfoCustomParams.addData(DATA_SIGNER_ID_KEY, privateKey.identifier);
      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(data);
      const finishEncryption = recipientCipher.finishEncryption();
      return {
        messageInfo,
        processEncryption,
        finishEncryption,
      };
    } finally {
      messageInfoCustomParams.delete();
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

  private _decryptAndVerify(
    encryptedData: Uint8Array,
    messageInfo: Uint8Array,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
  ) {
    const foundation = getFoundationModules();
    const paddingParams = foundation.PaddingParams.newWithConstraints(
      VirgilCrypto.PADDING_LEN,
      VirgilCrypto.PADDING_LEN,
    );
    const recipientCipher = new foundation.RecipientCipher();
    recipientCipher.random = getRandom();
    recipientCipher.paddingParams = paddingParams;
    let decryptedData: BufferType;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        privateKey.lowLevelPrivateKey,
        messageInfo,
      );
      const processDecryption = recipientCipher.processDecryption(encryptedData);
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

  private _decryptThenVerify(
    encryptedData: Uint8Array,
    messageInfo: Uint8Array,
    privateKey: VirgilPrivateKey,
    publicKeys: VirgilPublicKey[],
  ) {
    const foundation = getFoundationModules();
    const paddingParams = foundation.PaddingParams.newWithConstraints(
      VirgilCrypto.PADDING_LEN,
      VirgilCrypto.PADDING_LEN,
    );
    const recipientCipher = new foundation.RecipientCipher();
    recipientCipher.random = getRandom();
    recipientCipher.paddingParams = paddingParams;
    let decryptedData: BufferType;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        privateKey.lowLevelPrivateKey,
        messageInfo,
      );
      const processDecryption = recipientCipher.processDecryption(encryptedData);
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
        messageInfoCustomParams.delete();
        paddingParams.delete();
        recipientCipher.delete();
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
      messageInfoCustomParams.delete();
      paddingParams.delete();
      recipientCipher.delete();
    }
  }
}
