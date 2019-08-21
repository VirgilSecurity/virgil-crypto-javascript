export interface IPrivateKey {}

export interface IPublicKey {}

export interface IKeyPair {
  privateKey: IPrivateKey;
  publicKey: IPublicKey;
}

export interface ICrypto {
  generateKeys(keyPairType?: unknown): IKeyPair;
  generateKeysFromKeyMaterial(keyMaterial: Uint8Array, keyPairType?: unknown): IKeyPair;
  importPrivateKey(rawPrivateKey: Uint8Array): IPrivateKey;
  exportPrivateKey(privateKey: IPrivateKey): Uint8Array;
  importPublicKey(rawPublicKey: Uint8Array): IPublicKey;
  exportPublicKey(publicKey: IPublicKey): Uint8Array;
  encrypt(data: Uint8Array, publicKey: IPublicKey | IPublicKey[]): Uint8Array;
  decrypt(encryptedData: Uint8Array, privateKey: IPrivateKey): Uint8Array;
  calculateHash(data: Uint8Array, algorithm?: unknown): Uint8Array;
  extractPublicKey(privateKey: IPrivateKey): IPublicKey;
  calculateSignature(data: Uint8Array, privateKey: IPrivateKey): Uint8Array;
  verifySignature(data: Uint8Array, signature: Uint8Array, publicKey: IPublicKey): boolean;
  signThenEncrypt(
    data: Uint8Array,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): Uint8Array;
  decryptThenVerify(
    encryptedData: Uint8Array,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): Uint8Array;
  getRandomBytes(length: number): Uint8Array;
  signThenEncryptDetached(
    data: Uint8Array,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): { encryptedData: Uint8Array, metadata: Uint8Array };
  decryptThenVerifyDetached(
    encryptedData: Uint8Array,
    metadata: Uint8Array,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): Uint8Array;
}

export interface IAccessTokenSigner {
  getAlgorithm(): string;
  generateTokenSignature(
    token: Uint8Array,
    privateKey: IPrivateKey,
  ): Uint8Array;
  verifyTokenSignature(
    token: Uint8Array,
    signature: Uint8Array,
    publicKey: IPublicKey,
  ): boolean;
}

export interface ICardCrypto {
  generateSignature(data: Uint8Array, privateKey: IPrivateKey): Uint8Array;
  verifySignature(data: Uint8Array, signature: Uint8Array, publicKey: IPublicKey): boolean;
  exportPublicKey(publicKey: IPublicKey): Uint8Array;
  importPublicKey(rawPublicKey: Uint8Array): IPublicKey;
  generateSha512(data: Uint8Array): Uint8Array;
}

export interface IPrivateKeyExporter {
  exportPrivateKey(privateKey: IPrivateKey): Uint8Array;
  importPrivateKey(rawPrivateKey: Uint8Array): IPrivateKey;
}
