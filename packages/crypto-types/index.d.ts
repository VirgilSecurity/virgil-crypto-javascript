export type StringEncoding = BufferEncoding;

export interface StringWithEncoding {
  value: string;
  encoding: StringEncoding;
}

export type Data = Uint8Array | StringWithEncoding | string;

export interface IPrivateKey {}

export interface IPublicKey {}

export interface IKeyPair {
  privateKey: IPrivateKey;
  publicKey: IPublicKey;
}

export interface ICrypto {
  generateKeys(keyPairType?: unknown): IKeyPair;
  generateKeysFromKeyMaterial(keyMaterial: Data, keyPairType?: unknown): IKeyPair;
  importPrivateKey(rawPrivateKey: Data): IPrivateKey;
  exportPrivateKey(privateKey: IPrivateKey): Buffer;
  importPublicKey(rawPublicKey: Data): IPublicKey;
  exportPublicKey(publicKey: IPublicKey): Buffer;
  encrypt(data: Data, publicKey: IPublicKey | IPublicKey[]): Buffer;
  decrypt(encryptedData: Data, privateKey: IPrivateKey): Buffer;
  calculateHash(data: Data, algorithm?: unknown): Buffer;
  extractPublicKey(privateKey: IPrivateKey): IPublicKey;
  calculateSignature(data: Data, privateKey: IPrivateKey): Buffer;
  verifySignature(data: Data, signature: Data, publicKey: IPublicKey): boolean;
  signThenEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): Buffer;
  decryptThenVerify(
    encryptedData: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): Buffer;
  getRandomBytes(length: number): Buffer;
  signThenEncryptDetached(
    data: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): { encryptedData: Buffer, metadata: Buffer };
  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): Buffer;
}

export interface IAccessTokenSigner {
  getAlgorithm(): string;
  generateTokenSignature(
    token: Data,
    privateKey: IPrivateKey,
  ): Buffer;
  verifyTokenSignature(
    token: Data,
    signature: Data,
    publicKey: IPublicKey,
  ): boolean;
}

export interface ICardCrypto {
  generateSignature(data: Data, privateKey: IPrivateKey): Buffer;
  verifySignature(data: Data, signature: Data, publicKey: IPublicKey): boolean;
  exportPublicKey(publicKey: IPublicKey): Buffer;
  importPublicKey(rawPublicKey: Data): IPublicKey;
  generateSha512(data: Data): Buffer;
}

export interface IPrivateKeyExporter {
  exportPrivateKey(privateKey: IPrivateKey): Buffer;
  importPrivateKey(rawPrivateKey: Data): IPrivateKey;
}
