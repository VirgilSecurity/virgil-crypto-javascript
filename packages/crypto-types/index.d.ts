/// <reference types="node" />

export type StringEncoding = BufferEncoding;

export type NodeBuffer = Buffer;

export interface StringWithEncoding {
  value: string;
  encoding: StringEncoding;
}

export type Data = NodeBuffer | Uint8Array | StringWithEncoding | string;

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
  ): { encryptedData: NodeBuffer; metadata: NodeBuffer };
  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey | IPublicKey[],
  ): NodeBuffer;
}

export interface IAccessTokenSigner {
  getAlgorithm(): string;
  generateTokenSignature(token: Data, privateKey: IPrivateKey): NodeBuffer;
  verifyTokenSignature(token: Data, signature: Data, publicKey: IPublicKey): boolean;
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

export interface IPythiaTransformationKeyPair {
  privateKey: NodeBuffer;
  publicKey: NodeBuffer;
}

export interface IBrainKeyCrypto {
  blind(password: Data): { blindedPassword: NodeBuffer; blindingSecret: NodeBuffer };
  deblind(options: { transformedPassword: Data; blindingSecret: Data }): NodeBuffer;
}

export interface IPythiaCrypto {
  computeTransformationKeyPair(options: {
    transformationKeyId: Data;
    pythiaSecret: Data;
    pythiaScopeSecret: Data;
  }): IPythiaTransformationKeyPair;
  transform(options: {
    blindedPassword: Data;
    tweak: Data;
    transformationPrivateKey: Data;
  }): { transformedPassword: NodeBuffer; transformedTweak: NodeBuffer };
  prove(options: {
    transformedPassword: Data;
    blindedPassword: Data;
    transformedTweak: Data;
    transformationKeyPair: IPythiaTransformationKeyPair;
  }): { proofValueC: NodeBuffer; proofValueU: NodeBuffer };
  verify(options: {
    transformedPassword: Data;
    blindedPassword: Data;
    tweak: Data;
    transformationPublicKey: Data;
    proofValueC: Data;
    proofValueU: Data;
  }): boolean;
  getPasswordUpdateToken(options: {
    oldTransformationPrivateKey: Data;
    newTransformationPrivateKey: Data;
  }): NodeBuffer;
  updateDeblindedWithToken(options: {
    deblindedPassword: Data;
    updateToken: Data;
  }): NodeBuffer;
}
