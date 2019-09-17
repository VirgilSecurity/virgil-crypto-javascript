import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';
import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { FoundationModules, getFoundationModules } from './foundationModules';
import { HashAlgorithm, HashAlgorithmType } from './HashAlgorithm';
import { KeyPairType, KeyPairTypeType } from './KeyPairType';
import { importPrivateKey, importPublicKey } from './keyProvider';
import { serializePrivateKey, serializePublicKey } from './keySerializer';
import { getLowLevelPrivateKey } from './privateKeyUtils';
import { ICrypto, NodeBuffer as BufferType, Data } from './types';
import { toArray, getLowLevelPublicKeys } from './utils';
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

  private foundationModules: typeof FoundationModules;
  private random: FoundationModules.CtrDrbg;

  constructor(options: VirgilCryptoOptions = {}) {
    this.foundationModules = getFoundationModules();

    this.random = new this.foundationModules.CtrDrbg();
    try {
      this.random.setupDefaults();
    } catch (error) {
      this.random.delete();
      throw error;
    }

    this.defaultKeyPairType = options.defaultKeyPairType || KeyPairType.Default;
    this.useSha256Identifiers = options.useSha256Identifiers || false;
  }

  generateKeys(type?: KeyPairTypeType[keyof KeyPairTypeType]) {
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
      const serializedPublicKey = serializePublicKey(lowLevelPublicKey);
      const serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
      const identifier = this.calculateKeypairIdentifier(
        serializedPublicKey,
        this.useSha256Identifiers,
      );
      return {
        privateKey: new VirgilPrivateKey(identifier, serializedPrivateKey),
        publicKey: new VirgilPublicKey(identifier, serializedPublicKey),
      };
    } finally {
      keyProvider.delete();
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
    }
  }

  generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairTypeType[keyof KeyPairTypeType]) {
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
      const serializedPublicKey = serializePublicKey(lowLevelPublicKey);
      const serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
      const identifier = this.calculateKeypairIdentifier(
        serializedPublicKey,
        this.useSha256Identifiers,
      );
      return {
        privateKey: new VirgilPrivateKey(identifier, serializedPrivateKey),
        publicKey: new VirgilPublicKey(identifier, serializedPublicKey),
      };
    } finally {
      keyMaterialRng.delete();
      keyProvider.delete();
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
    }
  }

  importPrivateKey(rawPrivateKey: Data) {
    const serializedPrivateKey = dataToUint8Array(rawPrivateKey, 'base64');

    const lowLevelPrivateKey = importPrivateKey(serializedPrivateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    try {
      const serializedPublicKey = serializePublicKey(lowLevelPublicKey);
      const identifier = this.calculateKeypairIdentifier(
        serializedPublicKey,
        this.useSha256Identifiers,
      );
      return new VirgilPrivateKey(identifier, serializedPrivateKey);
    } finally {
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
    }
  }

  exportPrivateKey(privateKey: VirgilPrivateKey) {
    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    try {
      const serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
      return toBuffer(serializedPrivateKey);
    } finally {
      lowLevelPrivateKey.delete();
    }
  }

  importPublicKey(rawPublicKey: Data) {
    const serializedPublicKey = dataToUint8Array(rawPublicKey, 'base64');

    const lowLevelPublicKey = importPublicKey(serializedPublicKey);

    const identifier = this.calculateKeypairIdentifier(
      serializedPublicKey,
      this.useSha256Identifiers,
    );

    lowLevelPublicKey.delete();

    return new VirgilPublicKey(identifier, serializedPublicKey);
  }

  exportPublicKey(publicKey: VirgilPublicKey) {
    return toBuffer(publicKey.key);
  }

  encrypt(data: Data, publicKey: VirgilPublicKey | VirgilPublicKey[]) {
    const myData = dataToUint8Array(data, 'utf8');

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);
    const lowLevelPublicKeys = getLowLevelPublicKeys(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, lowLevelPublicKeys[index]);
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
      lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
    }
  }

  decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
    const myData = dataToUint8Array(encryptedData, 'base64');

    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        lowLevelPrivateKey,
        new Uint8Array(0),
      );
      const processDecryption = recipientCipher.processDecryption(myData);
      const finishDecryption = recipientCipher.finishDecryption();
      return NodeBuffer.concat([processDecryption, finishDecryption]);
    } finally {
      lowLevelPrivateKey.delete();
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
    validatePrivateKey(privateKey);

    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    try {
      const serializedPublicKey = serializePublicKey(lowLevelPublicKey);
      return new VirgilPublicKey(privateKey.identifier, serializedPublicKey);
    } finally {
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
    }
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
    try {
      const signature = signer.sign(lowLevelPrivateKey);
      return toBuffer(signature);
    } finally {
      signer.delete();
      sha512.delete();
      lowLevelPrivateKey.delete();
    }
  }

  verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
    const myData = dataToUint8Array(data, 'utf8');
    const mySignature = dataToUint8Array(signature, 'base64');

    validatePublicKey(publicKey);
    const lowLevelPublicKey = importPublicKey(publicKey.key);

    const verifier = new this.foundationModules.Verifier();
    try {
      verifier.reset(mySignature);
    } catch (error) {
      lowLevelPublicKey.delete();
      verifier.delete();
      throw error;
    }
    verifier.appendData(myData);

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
    const lowLevelPublicKeys = getLowLevelPublicKeys(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, lowLevelPublicKeys[index]);
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
      lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
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
    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

    let decryptedData: BufferType;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        lowLevelPrivateKey,
        new Uint8Array(0),
      );
      const processDecryption = recipientCipher.processDecryption(myEncryptedData);
      const finishDecryption = recipientCipher.finishDecryption();
      decryptedData = NodeBuffer.concat([processDecryption, finishDecryption]);
    } catch (error) {
      lowLevelPrivateKey.delete();
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
        lowLevelPrivateKey.delete();
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
        lowLevelPrivateKey.delete();
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
      lowLevelPrivateKey.delete();
      recipientCipher.delete();
      messageInfoCustomParams.delete();
    }
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
    const lowLevelPublicKeys = getLowLevelPublicKeys(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, lowLevelPublicKeys[index]);
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
      lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
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
    const myEncryptedData = dataToUint8Array(encryptedData, 'base64');
    const myMetadata = dataToUint8Array(metadata, 'base64');

    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const publicKeys = toArray(publicKey);
    validatePublicKeysArray(publicKeys);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

    let decryptedData: BufferType;
    try {
      recipientCipher.startDecryptionWithKey(privateKey.identifier, lowLevelPrivateKey, myMetadata);
      const processDecryption = recipientCipher.processDecryption(myEncryptedData);
      const finishDecryption = recipientCipher.finishDecryption();
      decryptedData = NodeBuffer.concat([processDecryption, finishDecryption]);
    } catch (error) {
      lowLevelPrivateKey.delete();
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
        lowLevelPrivateKey.delete();
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
        lowLevelPrivateKey.delete();
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
      lowLevelPrivateKey.delete();
      recipientCipher.delete();
      messageInfoCustomParams.delete();
    }
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

  generateGroupSession(groupId: Data) {
    const groupIdBytes = dataToUint8Array(groupId, 'utf8');
    if (groupIdBytes.byteLength < MIN_GROUP_ID_BYTE_LENGTH) {
      throw new Error(
        `The given group Id is too short. Must be at least ${MIN_GROUP_ID_BYTE_LENGTH} bytes.`,
      );
    }

    const sessionId = computeSessionId(groupIdBytes);
    const initialEpoch = createInitialEpoch(sessionId);

    const initialEpochMessage = initialEpoch.serialize();
    initialEpoch.delete();
    return createVirgilGroupSession([initialEpochMessage]);
  }

  importGroupSession(epochMessages: Data[]) {
    if (!Array.isArray(epochMessages)) {
      throw new TypeError('Epoch messages must be an array.');
    }

    if (epochMessages.length === 0) {
      throw new Error('Epoch messages must not be empty.');
    }

    return createVirgilGroupSession(epochMessages.map(it => dataToUint8Array(it, 'base64')));
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
}
