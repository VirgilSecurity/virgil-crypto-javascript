import { FoundationModules } from '@virgilsecurity/core-foundation';
import { NodeBuffer, dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { getFoundationModules } from './foundationModules';
import { HashAlgorithm, HashAlgorithmType } from './HashAlgorithm';
import { KeyPairType, KeyPairTypeType } from './KeyPairType';
import { importPrivateKey, importPublicKey } from './keyProvider';
import { serializePrivateKey, serializePublicKey } from './keySerializer';
import { getLowLevelPrivateKey } from './privateKeyUtils';
import {
  ICrypto,
  NodeBuffer as BufferType,
  Data,
  LowLevelPrivateKey,
  LowLevelPublicKey,
} from './types';
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
      keyProvider.setRsaParams(keyPairType.bitlen);
    }

    let lowLevelPrivateKey: LowLevelPrivateKey | undefined;
    try {
      lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
    } catch (error) {
      keyProvider.delete();
      throw error;
    }
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    let serializedPublicKey: Uint8Array | undefined;
    let serializedPrivateKey: Uint8Array | undefined;
    try {
      serializedPublicKey = serializePublicKey(lowLevelPublicKey);
    } catch (error) {
      keyProvider.delete();
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
      throw error;
    }
    try {
      serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
    } catch (error) {
      keyProvider.delete();
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
      throw error;
    }

    const identifier = this.calculateKeypairIdentifier(
      serializedPublicKey,
      this.useSha256Identifiers,
    );
    const keyPair = {
      privateKey: new VirgilPrivateKey(identifier, serializedPrivateKey),
      publicKey: new VirgilPublicKey(identifier, serializedPublicKey),
    };

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
    try {
      keyProvider.setupDefaults();
    } catch (error) {
      keyMaterialRng.delete();
      keyProvider.delete();
      throw error;
    }
    keyProvider.random = keyMaterialRng;
    if (keyPairType.algId === this.foundationModules.AlgId.RSA) {
      keyProvider.setRsaParams(keyPairType.bitlen);
    }

    let lowLevelPrivateKey: LowLevelPrivateKey | undefined;
    try {
      lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
    } catch (error) {
      keyMaterialRng.delete();
      keyProvider.delete();
      throw error;
    }
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    let serializedPublicKey: Uint8Array | undefined;
    let serializedPrivateKey: Uint8Array | undefined;
    try {
      serializedPublicKey = serializePublicKey(lowLevelPublicKey);
    } catch (error) {
      keyMaterialRng.delete();
      keyProvider.delete();
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
      throw error;
    }
    try {
      serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
    } catch (error) {
      keyMaterialRng.delete();
      keyProvider.delete();
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
      throw error;
    }

    const identifier = this.calculateKeypairIdentifier(
      serializedPublicKey,
      this.useSha256Identifiers,
    );
    const keyPair = {
      privateKey: new VirgilPrivateKey(identifier, serializedPrivateKey),
      publicKey: new VirgilPublicKey(identifier, serializedPublicKey),
    };

    keyMaterialRng.delete();
    keyProvider.delete();
    lowLevelPrivateKey.delete();
    lowLevelPublicKey.delete();

    return keyPair;
  }

  importPrivateKey(rawPrivateKey: Data) {
    const serializedPrivateKey = dataToUint8Array(rawPrivateKey, 'base64');

    const lowLevelPrivateKey = importPrivateKey(serializedPrivateKey);
    const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

    let serializedPublicKey: Uint8Array | undefined;
    try {
      serializedPublicKey = serializePublicKey(lowLevelPublicKey);
    } catch (error) {
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
      throw error;
    }

    const identifier = this.calculateKeypairIdentifier(
      serializedPublicKey,
      this.useSha256Identifiers,
    );
    const virgilPrivateKey = new VirgilPrivateKey(identifier, serializedPrivateKey);

    lowLevelPrivateKey.delete();
    lowLevelPublicKey.delete();

    return virgilPrivateKey;
  }

  exportPrivateKey(privateKey: VirgilPrivateKey) {
    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    let serializedPrivateKey: Uint8Array | undefined;
    try {
      serializedPrivateKey = serializePrivateKey(lowLevelPrivateKey);
    } catch (error) {
      lowLevelPrivateKey.delete();
      throw error;
    }

    lowLevelPrivateKey.delete();

    return toBuffer(serializedPrivateKey);
  }

  importPublicKey(rawPublicKey: Data) {
    const serializedPublicKey = dataToUint8Array(rawPublicKey, 'base64');

    const lowLevelPublicKey = importPublicKey(serializedPublicKey);

    const identifier = this.calculateKeypairIdentifier(
      serializedPublicKey,
      this.useSha256Identifiers,
    );
    const virgilPublicKey = new VirgilPublicKey(identifier, serializedPublicKey);

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

    const lowLevelPublicKeys: LowLevelPublicKey[] = [];
    publicKeys.forEach(({ key }) => {
      try {
        const lowLevelPublicKey = importPublicKey(key);
        lowLevelPublicKeys.push(lowLevelPublicKey);
      } catch (error) {
        lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
        throw error;
      }
    });

    const recipientCipher = new this.foundationModules.RecipientCipher();
    const aes256Gcm = new this.foundationModules.Aes256Gcm();
    recipientCipher.encryptionCipher = aes256Gcm;
    recipientCipher.random = this.random;

    publicKeys.forEach(({ identifier }, index) => {
      recipientCipher.addKeyRecipient(identifier, lowLevelPublicKeys[index]);
    });

    let result: BufferType | undefined;
    try {
      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();
      result = NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
    } catch (error) {
      recipientCipher.delete();
      aes256Gcm.delete();
      lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
      throw error;
    }

    recipientCipher.delete();
    aes256Gcm.delete();
    lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return result!;
  }

  decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
    const myData = dataToUint8Array(encryptedData, 'base64');
    validatePrivateKey(privateKey);
    const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

    const recipientCipher = new this.foundationModules.RecipientCipher();
    recipientCipher.random = this.random;

    let result: BufferType | undefined;
    try {
      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        lowLevelPrivateKey,
        new Uint8Array(0),
      );
      const processDecryption = recipientCipher.processDecryption(myData);
      const finishDecryption = recipientCipher.finishDecryption();
      result = NodeBuffer.concat([processDecryption, finishDecryption]);
    } catch (error) {
      lowLevelPrivateKey.delete();
      recipientCipher.delete();
      throw error;
    }

    lowLevelPrivateKey.delete();
    recipientCipher.delete();

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return result!;
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

    let serializedPublicKey: Uint8Array | undefined;
    try {
      serializedPublicKey = serializePublicKey(lowLevelPublicKey);
    } catch (error) {
      lowLevelPrivateKey.delete();
      lowLevelPublicKey.delete();
      throw error;
    }
    const virgilPublicKey = new VirgilPublicKey(privateKey.identifier, serializedPublicKey);

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

    let signature: Uint8Array | undefined;
    signer.reset();
    signer.appendData(myData);
    try {
      signature = signer.sign(lowLevelPrivateKey);
    } catch (error) {
      signer.delete();
      sha512.delete();
      lowLevelPrivateKey.delete();
      throw error;
    }

    signer.delete();
    sha512.delete();
    lowLevelPrivateKey.delete();

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return toBuffer(signature!);
  }

  verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
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

    let lowLevelPublicKey: LowLevelPublicKey | undefined;
    try {
      lowLevelPublicKey = importPublicKey(publicKey.key);
    } catch (error) {
      verifier.delete();
      throw error;
    }

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
    const lowLevelPublicKeys: LowLevelPublicKey[] = [];
    publicKeys.forEach(({ key }) => {
      try {
        const lowLevelPublicKey = importPublicKey(key);
        lowLevelPublicKeys.push(lowLevelPublicKey);
      } catch (error) {
        lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
        throw error;
      }
    });

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

    let result: BufferType | undefined;
    try {
      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();
      result = NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
    } catch (error) {
      lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
      recipientCipher.delete();
      aes256Gcm.delete();
      messageInfoCustomParams.delete();
      throw error;
    }

    lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
    recipientCipher.delete();
    aes256Gcm.delete();
    messageInfoCustomParams.delete();

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return result!;
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

    let decryptedData: BufferType | undefined;
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
      let signerId: Uint8Array | undefined;
      try {
        signerId = messageInfoCustomParams.findData(DATA_SIGNER_ID_KEY);
      } catch (error) {
        lowLevelPrivateKey.delete();
        recipientCipher.delete();
        messageInfoCustomParams.delete();
        throw error;
      }
      for (let i = 0; i < publicKeys.length; i += 1) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        if (NodeBuffer.compare(signerId!, publicKeys[i].identifier) === 0) {
          signerPublicKey = publicKeys[i];
          break;
        }
      }
      if (!signerPublicKey) {
        throw new Error('Signer not found');
      }
    }

    let signature: Uint8Array | undefined;
    try {
      signature = messageInfoCustomParams.findData(DATA_SIGNATURE_KEY);
    } catch (error) {
      lowLevelPrivateKey.delete();
      recipientCipher.delete();
      messageInfoCustomParams.delete();
      throw error;
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const isValid = this.verifySignature(decryptedData!, signature!, signerPublicKey);
    if (!isValid) {
      throw new Error('Invalid signature');
    }

    lowLevelPrivateKey.delete();
    recipientCipher.delete();
    messageInfoCustomParams.delete();

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return decryptedData!;
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
    const lowLevelPublicKeys: LowLevelPublicKey[] = [];
    publicKeys.forEach(publicKey => {
      try {
        const lowLevelPublicKey = importPublicKey(publicKey.key);
        lowLevelPublicKeys.push(lowLevelPublicKey);
      } catch (error) {
        lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
        throw error;
      }
    });

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

    let encryptedData: BufferType | undefined;
    let metadata: BufferType | undefined;
    try {
      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();
      encryptedData = NodeBuffer.concat([processEncryption, finishEncryption]);
      metadata = toBuffer(messageInfo);
    } catch (error) {
      lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
      recipientCipher.delete();
      aes256Gcm.delete();
      messageInfoCustomParams.delete();
      throw error;
    }

    lowLevelPublicKeys.forEach(lowLevelPublicKey => lowLevelPublicKey.delete());
    recipientCipher.delete();
    aes256Gcm.delete();
    messageInfoCustomParams.delete();

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return { encryptedData: encryptedData!, metadata: metadata! };
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

    let decryptedData: BufferType | undefined;
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
      let signerId: Uint8Array | undefined;
      try {
        signerId = messageInfoCustomParams.findData(DATA_SIGNER_ID_KEY);
      } catch (error) {
        lowLevelPrivateKey.delete();
        recipientCipher.delete();
        messageInfoCustomParams.delete();
        throw error;
      }
      for (let i = 0; i < publicKeys.length; i += 1) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        if (NodeBuffer.compare(signerId!, publicKeys[i].identifier) === 0) {
          signerPublicKey = publicKeys[i];
          break;
        }
      }
      if (!signerPublicKey) {
        throw new Error('Signer not found');
      }
    }

    let signature: Uint8Array | undefined;
    try {
      signature = messageInfoCustomParams.findData(DATA_SIGNATURE_KEY);
    } catch (error) {
      lowLevelPrivateKey.delete();
      recipientCipher.delete();
      messageInfoCustomParams.delete();
      throw error;
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const isValid = this.verifySignature(decryptedData!, signature!, signerPublicKey);
    if (!isValid) {
      throw new Error('Invalid signature');
    }

    lowLevelPrivateKey.delete();
    recipientCipher.delete();
    messageInfoCustomParams.delete();

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return decryptedData!;
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
}
