declare namespace PheModules {
  export class PheObject {
    delete(): void;
  }

  export interface Random {
    random(dataLen: number): Uint8Array;
    reseed(): void;
  }

  export interface Hash {
    DIGEST_LEN: number;
    BLOCK_LEN: number;
    hash(data: Uint8Array): Uint8Array;
    start(): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
  }

  export interface Kdf {
    derive(data: Uint8Array, keyLen: number): Uint8Array;
  }

  export interface SaltedKdf {
    reset(salt: Uint8Array, iterationCount: number): void;
    setInfo(info: Uint8Array): void;
  }

  export interface Mac {
    digestLen(): number;
    mac(key: Uint8Array, data: Uint8Array): Uint8Array;
    start(key: Uint8Array): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
    reset(): void;
  }

  export class PheCipher extends PheObject {
    random: Random;
    setupDefaults(): void;
    encryptLen(plainTextLen: number): number;
    decryptLen(cipherTextLen: number): number;
    encrypt(plainText: Uint8Array, accountKey: Uint8Array): Uint8Array;
    decrypt(cipherText: Uint8Array, accountKey: Uint8Array): Uint8Array;
    authEncrypt(
      plainText: Uint8Array,
      additionalData: Uint8Array,
      accountKey: Uint8Array,
    ): Uint8Array;
    authDecrypt(
      cipherText: Uint8Array,
      additionalData: Uint8Array,
      accountKey: Uint8Array,
    ): Uint8Array;
  }

  export class PheClient extends PheObject {
    random: Random;
    operationRandom: Random;
    setupDefaults(): void;
    setKeys(clientPrivateKey: Uint8Array, serverPublicKey: Uint8Array): void;
    generateClientPrivateKey(): Uint8Array;
    enrollmentRecordLen(): number;
    enrollAccount(
      enrollmentResponse: Uint8Array,
      password: Uint8Array,
    ): { enrollmentRecord: Uint8Array; accountKey: Uint8Array };
    verifyPasswordRequestLen(): number;
    createVerifyPasswordRequest(password: Uint8Array, enrollmentRecord: Uint8Array): Uint8Array;
    checkResponseAndDecrypt(
      password: Uint8Array,
      enrollmentRecord: Uint8Array,
      verifyPasswordResponse: Uint8Array,
    ): Uint8Array;
    rotateKeys(
      updateToken: Uint8Array,
    ): { newClientPrivateKey: Uint8Array; newServerPublicKey: Uint8Array };
    updateEnrollmentRecord(enrollmentRecord: Uint8Array, updateToken: Uint8Array): Uint8Array;
  }

  export class PheServer extends PheObject {
    random: Random;
    operationRandom: Random;
    setupDefaults(): void;
    generateServerKeyPair(): { serverPrivateKey: Uint8Array; serverPublicKey: Uint8Array };
    generateServerKeyPair(): number;
    getEnrollment(serverPrivateKey: Uint8Array, serverPublicKey: Uint8Array): Uint8Array;
    verifyPasswordResponseLen(): number;
    verifyPassword(
      serverPrivateKey: Uint8Array,
      serverPublicKey: Uint8Array,
      verifyPasswordRequest: Uint8Array,
    ): Uint8Array;
    updateTokenLen(): number;
    rotateKeys(
      serverPrivateKey: Uint8Array,
    ): { newServerPrivateKey: Uint8Array; newServerPublicKey: Uint8Array; updateToken: Uint8Array };
  }

  export class CtrDrbg extends PheObject implements Random {
    RESEED_INTERVAL: number;
    ENTROPY_LEN: number;
    random(dataLen: number): Uint8Array;
    reseed(): void;
    setupDefaults(): void;
    enablePredictionResistance(): void;
    setReseedInterval(interval: number): void;
    setReseedInterval(len: number): void;
  }

  export class Hkdf extends PheObject implements Kdf, SaltedKdf {
    hash: Hash;
    derive(data: Uint8Array, keyLen: number): Uint8Array;
    reset(salt: Uint8Array, iterationCount: number): void;
    setInfo(info: Uint8Array): void;
  }

  export class Hmac extends PheObject implements Mac {
    hash: Hash;
    digestLen(): number;
    mac(key: Uint8Array, data: Uint8Array): Uint8Array;
    start(key: Uint8Array): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
    reset(): void;
  }

  export class Sha512 extends PheObject implements Hash {
    DIGEST_LEN: number;
    BLOCK_LEN: number;
    hash(data: Uint8Array): Uint8Array;
    start(): void;
    update(data: Uint8Array): void;
    finish(): Uint8Array;
  }
}

declare module '@virgilsecurity/core-phe' {
  function initPhe(): Promise<typeof PheModules>;
  export default initPhe;
}

declare module '@virgilsecurity/core-phe/*' {
  function initPhe(): Promise<typeof PheModules>;
  export default initPhe;
}
