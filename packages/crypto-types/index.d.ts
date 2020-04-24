/* eslint-disable @typescript-eslint/interface-name-prefix */

/// <reference types="node" />

export type StringEncoding = BufferEncoding;

export type NodeBuffer = Buffer;

export interface StringWithEncoding {
  value: string;
  encoding: StringEncoding;
}

export type Data = NodeBuffer | Uint8Array | StringWithEncoding | string;

export interface IPrivateKey {
  identifier: NodeBuffer;
}

export interface IPublicKey {
  identifier: NodeBuffer;
}

export interface IKeyPair {
  privateKey: IPrivateKey;
  publicKey: IPublicKey;
}

export interface IGroupSessionMessageInfo {
  sessionId: string;
  epochNumber: number;
  data: string;
}

export interface IGroupSession {
  getSessionId(): string;
  getCurrentEpochNumber(): number;
  encrypt(data: Data, signingPrivateKey: IPrivateKey): NodeBuffer;
  decrypt(encryptedData: Data, verifyingPublicKey: IPublicKey): NodeBuffer;
  addNewEpoch(): IGroupSessionMessageInfo;
  export(): NodeBuffer[];
  parseMessage(messageData: Data): IGroupSessionMessageInfo;
}

export interface ICrypto {
  generateKeys(keyPairType?: unknown): IKeyPair;
  generateKeysFromKeyMaterial(keyMaterial: Data, keyPairType?: unknown): IKeyPair;
  importPrivateKey(rawPrivateKey: Data): IPrivateKey;
  exportPrivateKey(privateKey: IPrivateKey): NodeBuffer;
  importPublicKey(rawPublicKey: Data): IPublicKey;
  exportPublicKey(publicKey: IPublicKey): NodeBuffer;
  encrypt(data: Data, publicKey: IPublicKey, enablePadding?: boolean): NodeBuffer;
  encrypt(data: Data, publicKeys: IPublicKey[], enablePadding?: boolean): NodeBuffer;
  encrypt(
    data: Data,
    publicKeyOrPublicKeys: IPublicKey | IPublicKey[],
    enablePadding?: boolean,
  ): NodeBuffer;
  decrypt(encryptedData: Data, privateKey: IPrivateKey): NodeBuffer;
  calculateHash(data: Data, algorithm?: unknown): NodeBuffer;
  extractPublicKey(privateKey: IPrivateKey): IPublicKey;
  calculateSignature(data: Data, privateKey: IPrivateKey): NodeBuffer;
  verifySignature(data: Data, signature: Data, publicKey: IPublicKey): boolean;
  signAndEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey,
    enablePadding?: boolean,
  ): NodeBuffer;
  signAndEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKeys: IPublicKey[],
    enablePadding?: boolean,
  ): NodeBuffer;
  signAndEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKeyOrPublicKeys: IPublicKey | IPublicKey[],
    enablePadding?: boolean,
  ): NodeBuffer;
  signThenEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey,
    enablePadding?: boolean,
  ): NodeBuffer;
  signThenEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKeys: IPublicKey[],
    enablePadding?: boolean,
  ): NodeBuffer;
  signThenEncrypt(
    data: Data,
    privateKey: IPrivateKey,
    publicKeyOrPublicKeys: IPublicKey | IPublicKey[],
    enablePadding?: boolean,
  ): NodeBuffer;
  decryptAndVerify(encryptedData: Data, privateKey: IPrivateKey, publicKey: IPublicKey): NodeBuffer;
  decryptAndVerify(
    encryptedData: Data,
    privateKey: IPrivateKey,
    publicKeys: IPublicKey[],
  ): NodeBuffer;
  decryptAndVerify(
    encryptedData: Data,
    privateKey: IPrivateKey,
    publicKeyOrPublicKeys: IPublicKey | IPublicKey[],
  ): NodeBuffer;
  decryptThenVerify(
    encryptedData: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey,
  ): NodeBuffer;
  decryptThenVerify(
    encryptedData: Data,
    privateKey: IPrivateKey,
    publicKeys: IPublicKey[],
  ): NodeBuffer;
  decryptThenVerify(
    encryptedData: Data,
    privateKey: IPrivateKey,
    publicKeyOrPublicKeys: IPublicKey | IPublicKey[],
  ): NodeBuffer;
  getRandomBytes(length: number): NodeBuffer;
  signThenEncryptDetached(
    data: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey,
    enablePadding?: boolean,
  ): { encryptedData: NodeBuffer; metadata: NodeBuffer };
  signThenEncryptDetached(
    data: Data,
    privateKey: IPrivateKey,
    publicKeys: IPublicKey[],
    enablePadding?: boolean,
  ): { encryptedData: NodeBuffer; metadata: NodeBuffer };
  signThenEncryptDetached(
    data: Data,
    privateKey: IPrivateKey,
    publicKeyOrPublicKeys: IPublicKey | IPublicKey[],
    enablePadding?: boolean,
  ): { encryptedData: NodeBuffer; metadata: NodeBuffer };
  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: IPrivateKey,
    publicKey: IPublicKey,
  ): NodeBuffer;
  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: IPrivateKey,
    publicKeys: IPublicKey[],
  ): NodeBuffer;
  decryptThenVerifyDetached(
    encryptedData: Data,
    metadata: Data,
    privateKey: IPrivateKey,
    publicKeyOrPublicKeys: IPublicKey | IPublicKey[],
  ): NodeBuffer;
  generateGroupSession(groupId: Data): IGroupSession;
  importGroupSession(epochMessages: Data[]): IGroupSession;
  calculateGroupSessionId(groupId: Data): string;
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

export interface IPythiaCrypto extends IBrainKeyCrypto {
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
  updateDeblindedWithToken(options: { deblindedPassword: Data; updateToken: Data }): NodeBuffer;
}
