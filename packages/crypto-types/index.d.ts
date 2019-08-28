/// <reference types="node" />

export type StringEncoding = BufferEncoding;

export type NodeBuffer = Buffer;

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
  exportPrivateKey(privateKey: IPrivateKey): NodeBuffer;
  importPublicKey(rawPublicKey: Data): IPublicKey;
  exportPublicKey(publicKey: IPublicKey): NodeBuffer;
  encrypt(data: Data, publicKey: IPublicKey | IPublicKey[]): NodeBuffer;
  decrypt(encryptedData: Data, privateKey: IPrivateKey): NodeBuffer;
  calculateHash(data: Data, algorithm?: unknown): NodeBuffer;
  extractPublicKey(privateKey: IPrivateKey): IPublicKey;
  calculateSignature(data: Data, privateKey: IPrivateKey): NodeBuffer;
  verifySignature(data: Data, signature: Data, publicKey: IPublicKey): boolean;
  signThenEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): NodeBuffer;
  decryptThenVerify(
    encryptedData: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): NodeBuffer;
  getRandomBytes(length: number): NodeBuffer;
  signThenEncryptDetached(
    data: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): { encryptedData: NodeBuffer, metadata: NodeBuffer };
  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): NodeBuffer;
}

export interface IAccessTokenSigner {
  getAlgorithm(): string;
  generateTokenSignature(
    token: Data,
    privateKey: IPrivateKey,
  ): NodeBuffer;
  verifyTokenSignature(
    token: Data,
    signature: Data,
    publicKey: IPublicKey,
  ): boolean;
}

export interface ICardCrypto {
  generateSignature(data: Data, privateKey: IPrivateKey): NodeBuffer;
  verifySignature(data: Data, signature: Data, publicKey: IPublicKey): boolean;
  exportPublicKey(publicKey: IPublicKey): NodeBuffer;
  importPublicKey(rawPublicKey: Data): IPublicKey;
  generateSha512(data: Data): NodeBuffer;
}

export interface IPrivateKeyExporter {
  exportPrivateKey(privateKey: IPrivateKey): NodeBuffer;
  importPrivateKey(rawPrivateKey: Data): IPrivateKey;
}
