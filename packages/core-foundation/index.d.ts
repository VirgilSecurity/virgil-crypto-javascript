declare namespace FoundationModules {
  export enum AlgId {
    NONE = 0,
    SHA224 = 1,
    SHA256 = 2,
    SHA384 = 3,
    SHA512 = 4,
    KDF1 = 5,
    KDF2 = 6,
    RSA = 7,
    ECC = 8,
    ED25519 = 9,
    CURVE25519 = 10,
    SECP256R1 = 11,
    AES256_GCM = 12,
    AES256_CBC = 13,
    HMAC = 14,
    HKDF = 15,
    PKCS5_PBKDF2 = 16,
    PKCS5_PBES2 = 17,
  }

  export enum GroupMsgType {
    GROUP_INFO = 0,
    REGULAR = 1,
  }

  export class FoundationObject {
    delete(): void;
  }

  export interface AlgInfo {
    algId(): AlgId;
  }

  export interface Key {
    algId(): AlgId;
    algInfo(): AlgInfo;
    len(): number;
    bitlen(): number;
    isValid(): boolean;
  }

  export interface PrivateKey extends FoundationObject, Key {
    extractPublicKey(): PublicKey;
  }

  export interface PublicKey extends FoundationObject, Key {}

  export class GroupSessionMessage extends FoundationObject {
    getEpoch(): number;
    getSessionId(): Uint8Array;
    serialize(): Uint8Array;
    static deserialize(data: Uint8Array): GroupSessionMessage;
  }

  export class GroupSessionTicket extends FoundationObject {
    rng: Random;
    setupTicketAsNew(sessionId: Uint8Array): void;
    getTicketMessage(): GroupSessionMessage;
  }

  export class GroupSession extends FoundationObject {
    rng: Random;
    addEpoch(message: GroupSessionMessage): void;
    getSessionId(): Uint8Array;
    getCurrentEpoch(): number;
    createGroupTicket(): GroupSessionTicket;
    encrypt(data: Uint8Array, privateKey: PrivateKey): GroupSessionMessage;
    decrypt(message: GroupSessionMessage, publicKey: PublicKey): Uint8Array;
  }

  export interface Random {
    random(dataLen: number): Uint8Array;
    reseed(): void;
  }

  export class CtrDrbg extends FoundationObject implements Random {
    setupDefaults(): void;
    random(dataLen: number): Uint8Array;
    reseed(): void;
  }

  export class KeyMaterialRng extends FoundationObject implements Random {
    random(dataLen: number): Uint8Array;
    reseed(): void;
    resetKeyMaterial(keyMaterial: Uint8Array): void;
  }

  export interface Hash {
    DIGEST_LEN: number;
    BLOCK_LEN: number;
    hash(data: Uint8Array): Uint8Array;
    start(): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
  }

  export class Sha224 extends FoundationObject implements Hash {
    DIGEST_LEN: number;
    BLOCK_LEN: number;
    hash(data: Uint8Array): Uint8Array;
    start(): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
  }

  export class Sha256 extends FoundationObject implements Hash {
    DIGEST_LEN: number;
    BLOCK_LEN: number;
    hash(data: Uint8Array): Uint8Array;
    start(): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
  }

  export class Sha384 extends FoundationObject implements Hash {
    DIGEST_LEN: number;
    BLOCK_LEN: number;
    hash(data: Uint8Array): Uint8Array;
    start(): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
  }

  export class Sha512 extends FoundationObject implements Hash {
    DIGEST_LEN: number;
    BLOCK_LEN: number;
    hash(data: Uint8Array): Uint8Array;
    start(): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
  }

  export class KeyProvider extends FoundationObject {
    random: Random;
    setupDefaults(): void;
    setRsaParams(bitLen: number): void;
    generatePrivateKey(algId: AlgId): PrivateKey;
    importPrivateKey(keyData: Uint8Array): PrivateKey;
    importPublicKey(keyData: Uint8Array): PublicKey;
    exportPublicKey(publicKey: PublicKey): Uint8Array;
    exportPrivateKey(privateKey: PrivateKey): Uint8Array;
  }

  export class KeyAsn1Serializer extends FoundationObject {
    setupDefaults(): void;
    serializePrivateKey(lowLevelPrivateKey: PrivateKey): Uint8Array;
    serializePublicKey(lowLevelPublicKey: PublicKey): Uint8Array;
  }

  export interface Cipher {
    setNonce(nonce: Uint8Array): void;
    setKey(key: Uint8Array): void;
    startEncryption(): void;
    startDecryption(): void;
    update(data: Uint8Array): Uint8Array;
    outLen(dataLen: number): number;
    encryptedOutLen(dataLen: number): number;
    decryptedOutLen(dataLen: number): number;
    finish(): Uint8Array;
  }

  export class MessageInfoEditor extends FoundationObject {
    random: Random;
    setupDefaults(): void;
    unpack(messageInfoData: Uint8Array): void;
    unlock(ownerRecipientId: Uint8Array, ownerPrivateKey: PrivateKey): void;
    addKeyRecipient(recipientId: Uint8Array, publicKey: PublicKey): void;
    removeKeyRecipient(recipientId: Uint8Array): boolean;
    removeAll(): void;
    packedLen(): number;
    pack(): Uint8Array;
  }

  export class MessageInfoCustomParams extends FoundationObject {
    addData(key: Uint8Array, value: Uint8Array): void;
    findData(key: Uint8Array): Uint8Array;
  }

  export class Aes256Gcm extends FoundationObject implements Cipher {
    setNonce(nonce: Uint8Array): void;
    setKey(key: Uint8Array): void;
    startEncryption(): void;
    startDecryption(): void;
    update(data: Uint8Array): Uint8Array;
    outLen(dataLen: number): number;
    encryptedOutLen(dataLen: number): number;
    decryptedOutLen(dataLen: number): number;
    finish(): Uint8Array;
  }

  export class RecipientCipher extends FoundationObject {
    random: Random;
    encryptionCipher: Cipher;
    signerHash: Hash;
    hasKeyRecipient(hasKeyRecipient: Uint8Array): boolean;
    addKeyRecipient(recipientId: Uint8Array, publicKey: PublicKey): void;
    clearRecipients(): void;
    addSigner(signerId: Uint8Array, privateKey: PrivateKey): void;
    clearSigners(): void;
    customParams(): MessageInfoCustomParams;
    startEncryption(): void;
    startSignedEncryption(dataSize: number): void;
    messageInfoLen(): number;
    packMessageInfo(): Uint8Array;
    encryptionOutLen(dataLen: number): number;
    processEncryption(data: Uint8Array): Uint8Array;
    finishEncryption(): Uint8Array;
    startDecryptionWithKey(
      recipientId: Uint8Array,
      privateKey: PrivateKey,
      messageInfo: Uint8Array,
    ): void;
    startDecryptionWithKey(
      recipientId: Uint8Array,
      privateKey: PrivateKey,
      messageInfo: Uint8Array,
      messageInfoFooter: Uint8Array,
    ): void;
    decryptionOutLen(dataLen: number): number;
    processDecryption(data: Uint8Array): Uint8Array;
    finishDecryption(): Uint8Array;
    isDataSigned(): boolean;
    signerInfos(): SignerInfoList;
    verifySignerInfo(signerInfo: SignerInfo, publicKey: PublicKey): boolean;
    messageInfoFooterLen(): number;
    packMessageInfoFooter(): Uint8Array;
  }

  export class Signer extends FoundationObject {
    hash: Hash;
    random: Random;
    reset(): void;
    appendData(data: Uint8Array): void;
    signatureLen(privateKey: PrivateKey): number;
    sign(privateKey: PrivateKey): Uint8Array;
  }

  export class SignerInfo extends FoundationObject {
    signerId(): Uint8Array;
    signature(): Uint8Array;
  }

  export class SignerInfoList extends FoundationObject {
    hasItem(): boolean;
    item(): SignerInfo;
    hasNext(): boolean;
    next(): SignerInfoList;
    hasPrev(): boolean;
    prev(): SignerInfoList;
    clear(): void;
  }

  export class Verifier extends FoundationObject {
    reset(signature: Uint8Array): void;
    appendData(data: Uint8Array): void;
    verify(publicKey: PublicKey): boolean;
  }
}

declare module '@virgilsecurity/core-foundation' {
  function initFoundation(): Promise<typeof FoundationModules>;
  export default initFoundation;
}

declare module '@virgilsecurity/core-foundation/*' {
  function initFoundation(): Promise<typeof FoundationModules>;
  export default initFoundation;
}
