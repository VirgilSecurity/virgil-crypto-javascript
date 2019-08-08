import { FoundationModules } from '@virgilsecurity/core-foundation';
import { Buffer as NodeBuffer } from 'buffer';

import { DATA_SIGNATURE_KEY, DATA_SIGNER_ID_KEY } from './constants';
import { HashAlgorithmType } from './initHashAlgorithm';
import { KeyPairTypeType } from './initKeyPairType';
import { CryptoModules } from './initBaseCrypto';
import { getLowLevelPrivateKey } from './privateKeyUtils';
import { Data, LowLevelPrivateKey, LowLevelPublicKey } from './types';
import { dataToUint8Array, toArray, toBuffer } from './utils';
import { validatePrivateKey, validatePublicKey, validatePublicKeysArray } from './validators';
import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';

export interface VirgilCryptoOptions {
  useSha256Identifiers?: boolean;
  defaultKeyPairType?: KeyPairTypeType[keyof KeyPairTypeType];
}

export const initVirgilCrypto = (foundationModules: FoundationModules, modules: CryptoModules) => {
  const _random = new foundationModules.CtrDrbg();
  _random.setupDefaults();

  return class VirgilCrypto {
    readonly useSha256Identifiers: boolean;
    readonly defaultKeyPairType: KeyPairTypeType[keyof KeyPairTypeType];

    readonly hashAlgorithm = modules.HashAlgorithm;
    readonly keyPairType = modules.KeyPairType;

    constructor({
      useSha256Identifiers = false,
      defaultKeyPairType = modules.KeyPairType.Default,
    }: VirgilCryptoOptions = {}) {
      this.useSha256Identifiers = useSha256Identifiers;
      this.defaultKeyPairType = defaultKeyPairType;
    }

    generateKeys(type?: KeyPairTypeType[keyof KeyPairTypeType]) {
      const keyPairType = type ? type : this.defaultKeyPairType;

      const keyProvider = new foundationModules.KeyProvider();
      keyProvider.setupDefaults();
      if (keyPairType.algId === foundationModules.AlgId.RSA) {
        keyProvider.setRsaParams(keyPairType.bitlen);
      }

      const lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
      const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

      try {
        return this._wrapKeyPair(lowLevelPrivateKey, lowLevelPublicKey, this.useSha256Identifiers);
      } finally {
        keyProvider.delete();
      }
    }

    generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairTypeType[keyof KeyPairTypeType]) {
      const keyPairType = type ? type : this.defaultKeyPairType;
      const myKeyMaterial = dataToUint8Array(keyMaterial);

      const keyMaterialRng = new foundationModules.KeyMaterialRng();
      keyMaterialRng.resetKeyMaterial(myKeyMaterial);

      const keyProvider = new foundationModules.KeyProvider();
      keyProvider.setupDefaults();
      keyProvider.random = keyMaterialRng;
      if (keyPairType.algId === foundationModules.AlgId.RSA) {
        keyProvider.setRsaParams(keyPairType.bitlen);
      }

      const lowLevelPrivateKey = keyProvider.generatePrivateKey(keyPairType.algId);
      const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

      try {
        return this._wrapKeyPair(lowLevelPrivateKey, lowLevelPublicKey, this.useSha256Identifiers);
      } finally {
        keyMaterialRng.delete();
        keyProvider.delete();
      }
    }

    importPrivateKey(rawPrivateKey: Data) {
      const myRawPrivateKey = dataToUint8Array(rawPrivateKey);

      const keyProvider = new foundationModules.KeyProvider();
      keyProvider.setupDefaults();

      const lowLevelPrivateKey = keyProvider.importPrivateKey(myRawPrivateKey);
      const lowLevelPublicKey = lowLevelPrivateKey.extractPublicKey();

      const keyAsn1Serializer = new foundationModules.KeyAsn1Serializer();
      keyAsn1Serializer.setupDefaults();

      const serializedPublicKey = keyAsn1Serializer.serializePublicKey(lowLevelPublicKey);
      const identifier = this._calculateKeypairIdentifier(
        serializedPublicKey,
        this.useSha256Identifiers,
      );

      try {
        return new VirgilPrivateKey(identifier, lowLevelPrivateKey);
      } finally {
        keyProvider.delete();
        lowLevelPublicKey.delete();
        keyAsn1Serializer.delete();
      }
    }

    exportPrivateKey(privateKey: VirgilPrivateKey) {
      validatePrivateKey(privateKey);
      const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

      const keyAsn1Serializer = new foundationModules.KeyAsn1Serializer();
      keyAsn1Serializer.setupDefaults();

      const serializedPrivateKey = keyAsn1Serializer.serializePrivateKey(lowLevelPrivateKey);

      try {
        return toBuffer(serializedPrivateKey);
      } finally {
        keyAsn1Serializer.delete();
      }
    }

    importPublicKey(rawPublicKey: Data) {
      const myRawPublicKey = dataToUint8Array(rawPublicKey);

      const keyProvider = new foundationModules.KeyProvider();
      keyProvider.setupDefaults();

      const lowLevelPublicKey = keyProvider.importPublicKey(myRawPublicKey);

      const keyAsn1Serializer = new foundationModules.KeyAsn1Serializer();
      keyAsn1Serializer.setupDefaults();

      const serializedKey: Uint8Array = keyAsn1Serializer.serializePublicKey(lowLevelPublicKey);
      const identifier = this._calculateKeypairIdentifier(serializedKey, this.useSha256Identifiers);
      try {
        return new VirgilPublicKey(identifier, lowLevelPublicKey);
      } finally {
        keyProvider.delete();
        keyAsn1Serializer.delete();
      }
    }

    exportPublicKey(publicKey: VirgilPublicKey) {
      const keyAsn1Serializer = new foundationModules.KeyAsn1Serializer();
      keyAsn1Serializer.setupDefaults();

      const serializedPublicKey = keyAsn1Serializer.serializePublicKey(publicKey.key);

      try {
        return toBuffer(serializedPublicKey);
      } finally {
        keyAsn1Serializer.delete();
      }
    }

    encrypt(data: Data, publicKey: VirgilPublicKey | VirgilPublicKey[]) {
      const myData = dataToUint8Array(data);
      const publicKeys = toArray(publicKey);
      validatePublicKeysArray(publicKeys);

      const recipientCipher = new foundationModules.RecipientCipher();
      const aes256Gcm = new foundationModules.Aes256Gcm();
      recipientCipher.encryptionCipher = aes256Gcm;
      recipientCipher.random = _random;

      publicKeys.forEach(myPublicKey => {
        recipientCipher.addKeyRecipient(myPublicKey.identifier, myPublicKey.key);
      });

      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();

      try {
        return NodeBuffer.concat([messageInfo, processEncryption, finishEncryption]);
      } finally {
        recipientCipher.delete();
        aes256Gcm.delete();
      }
    }

    decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
      const myData = dataToUint8Array(encryptedData);
      validatePrivateKey(privateKey);
      const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

      const recipientCipher = new foundationModules.RecipientCipher();

      recipientCipher.startDecryptionWithKey(
        privateKey.identifier,
        lowLevelPrivateKey,
        new Uint8Array(0),
      );
      const processDecryption = recipientCipher.processDecryption(myData);
      const finishDecryption = recipientCipher.finishDecryption();

      try {
        return NodeBuffer.concat([processDecryption, finishDecryption]);
      } finally {
        recipientCipher.delete();
      }
    }

    calculateHash(
      data: Data,
      algorithm: HashAlgorithmType[keyof HashAlgorithmType] = modules.HashAlgorithm.SHA512,
    ) {
      const myData = dataToUint8Array(data);
      let result: Uint8Array;
      switch (algorithm) {
        case modules.HashAlgorithm.SHA224:
          result = this._createHash(myData, foundationModules.Sha224);
          break;
        case modules.HashAlgorithm.SHA256:
          result = this._createHash(myData, foundationModules.Sha256);
          break;
        case modules.HashAlgorithm.SHA384:
          result = this._createHash(myData, foundationModules.Sha384);
          break;
        case modules.HashAlgorithm.SHA512:
          result = this._createHash(myData, foundationModules.Sha512);
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
      return new VirgilPublicKey(privateKey.identifier, lowLevelPublicKey);
    }

    calculateSignature(data: Data, privateKey: VirgilPrivateKey) {
      const myData = dataToUint8Array(data);
      validatePrivateKey(privateKey);
      const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

      const signer = new foundationModules.Signer();
      const sha512 = new foundationModules.Sha512();
      signer.hash = sha512;

      signer.reset();
      signer.appendData(myData);
      const signature = signer.sign(lowLevelPrivateKey);

      try {
        return toBuffer(signature);
      } finally {
        signer.delete();
        sha512.delete();
      }
    }

    verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
      const myData = dataToUint8Array(data);
      const mySignature = dataToUint8Array(signature);
      validatePublicKey(publicKey);

      const verifier = new foundationModules.Verifier();

      verifier.reset(mySignature);
      verifier.appendData(myData);
      try {
        return verifier.verify(publicKey.key);
      } finally {
        verifier.delete();
      }
    }

    signThenEncrypt(
      data: Data,
      privateKey: VirgilPrivateKey,
      publicKey: VirgilPublicKey | VirgilPublicKey[],
    ) {
      const myData = dataToUint8Array(data);

      validatePrivateKey(privateKey);

      const publicKeys = toArray(publicKey);
      validatePublicKeysArray(publicKeys);

      const recipientCipher = new foundationModules.RecipientCipher();
      const aes256Gcm = new foundationModules.Aes256Gcm();
      recipientCipher.encryptionCipher = aes256Gcm;
      recipientCipher.random = _random;

      const signature = this.calculateSignature(myData, privateKey);
      publicKeys.forEach(publicKey => {
        recipientCipher.addKeyRecipient(publicKey.identifier, publicKey.key);
      });

      const messageInfoCustomParams = recipientCipher.customParams();
      messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, signature);
      messageInfoCustomParams.addData(DATA_SIGNER_ID_KEY, privateKey.identifier);

      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();

      try {
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
      const myEncryptedData = dataToUint8Array(encryptedData);

      const publicKeys = toArray(publicKey);
      validatePublicKeysArray(publicKeys);

      validatePrivateKey(privateKey);
      const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

      const recipientCipher = new foundationModules.RecipientCipher();

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

      try {
        return decryptedData;
      } finally {
        recipientCipher.delete();
        messageInfoCustomParams.delete();
      }
    }

    getRandomBytes(length: number) {
      const bytes = _random.random(length);
      return toBuffer(bytes);
    }

    signThenEncryptDetached(
      data: Data,
      privateKey: VirgilPrivateKey,
      publicKey: VirgilPublicKey | VirgilPublicKey[],
    ) {
      const myData = dataToUint8Array(data);

      validatePrivateKey(privateKey);

      const publicKeys = toArray(publicKey);
      validatePublicKeysArray(publicKeys);

      const recipientCipher = new foundationModules.RecipientCipher();
      const aes256Gcm = new foundationModules.Aes256Gcm();
      recipientCipher.encryptionCipher = aes256Gcm;
      recipientCipher.random = _random;

      const signature = this.calculateSignature(myData, privateKey);
      publicKeys.forEach(({ identifier, key }) => {
        recipientCipher.addKeyRecipient(identifier, key);
      });

      const messageInfoCustomParams = recipientCipher.customParams();
      messageInfoCustomParams.addData(DATA_SIGNATURE_KEY, signature);
      messageInfoCustomParams.addData(DATA_SIGNER_ID_KEY, privateKey.identifier);

      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(myData);
      const finishEncryption = recipientCipher.finishEncryption();

      try {
        return {
          encryptedData: NodeBuffer.concat([processEncryption, finishEncryption]),
          metadata: toBuffer(messageInfo),
        };
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
      const myEncryptedData = dataToUint8Array(encryptedData);
      const myMetadata = dataToUint8Array(metadata);

      validatePrivateKey(privateKey);
      const lowLevelPrivateKey = getLowLevelPrivateKey(privateKey);

      const publicKeys = toArray(publicKey);
      validatePublicKeysArray(publicKeys);

      const recipientCipher = new foundationModules.RecipientCipher();

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

      try {
        return decryptedData;
      } finally {
        recipientCipher.delete();
        messageInfoCustomParams.delete();
      }
    }

    createStreamCipher(publicKey: VirgilPublicKey | VirgilPublicKey[], signature?: Data) {
      return new modules.VirgilStreamCipher(publicKey, signature);
    }

    createStreamDecipher(privateKey: VirgilPrivateKey) {
      return new modules.VirgilStreamDecipher(privateKey);
    }

    createStreamSigner() {
      return new modules.VirgilStreamSigner();
    }

    createStreamVerifier(signature: Data) {
      return new modules.VirgilStreamVerifier(signature);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _createHash(data: Uint8Array, HashClass: any) {
      const hashInstance = new HashClass();
      try {
        return hashInstance.hash(data);
      } finally {
        hashInstance.delete();
      }
    }

    _calculateKeypairIdentifier(serializedPublicKey: Uint8Array, useSha256Identifiers: boolean) {
      if (useSha256Identifiers) {
        return this._createHash(serializedPublicKey, foundationModules.Sha256);
      }
      return this._createHash(serializedPublicKey, foundationModules.Sha512).slice(0, 8);
    }

    _wrapKeyPair(
      lowLevelPrivateKey: LowLevelPrivateKey,
      lowLevelPublicKey: LowLevelPublicKey,
      useSha256Identifiers: boolean,
    ) {
      const keyAsn1Serializer = new foundationModules.KeyAsn1Serializer();
      keyAsn1Serializer.setupDefaults();

      const serializedPublicKey: Uint8Array = keyAsn1Serializer.serializePublicKey(
        lowLevelPublicKey,
      );
      const identifier = this._calculateKeypairIdentifier(
        serializedPublicKey,
        useSha256Identifiers,
      );

      try {
        return {
          privateKey: new modules.VirgilPrivateKey(identifier, lowLevelPrivateKey),
          publicKey: new modules.VirgilPublicKey(identifier, lowLevelPublicKey),
        };
      } finally {
        keyAsn1Serializer.delete();
      }
    }
  };
};

export type VirgilCryptoReturnType = ReturnType<typeof initVirgilCrypto>;

export type VirgilCryptoType = InstanceType<VirgilCryptoReturnType>;
