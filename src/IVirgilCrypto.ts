import { HashAlgorithm, KeyPairType } from './common';
import { VirgilPrivateKey, VirgilPublicKey } from './VirgilCrypto';

export interface IPrivateKey {}

export interface IPublicKey {}

export interface IVirgilCrypto {
	generateKeys: (type?: KeyPairType | undefined) => {
		privateKey: VirgilPrivateKey;
		publicKey: VirgilPublicKey;
	};
	importPrivateKey: (rawPrivateKey: string | Buffer, password?: string | undefined) => VirgilPrivateKey;
	importPublicKey: (rawPublicKey: string | Buffer) => VirgilPublicKey;
	exportPrivateKey: (privateKey: IPrivateKey, password?: string | undefined) => Buffer;
	exportPublicKey: (publicKey: IPublicKey) => Buffer;
	extractPublicKey: (privateKey: IPrivateKey) => VirgilPublicKey;
	encrypt: (data: string | Buffer, publicKey: IPublicKey | IPublicKey[]) => Buffer;
	decrypt: (encryptedData: string | Buffer, privateKey: IPrivateKey) => Buffer;
	calculateSignature: (data: string | Buffer, privateKey: IPrivateKey) => Buffer;
	verifySignature: (data: string | Buffer, signature: string | Buffer, publicKey: IPublicKey) => boolean;
	calculateHash: (data: string | Buffer, algorithm?: HashAlgorithm) => Buffer;
	signThenEncrypt: (
		data: string | Buffer, signingKey: IPrivateKey, encryptionKey: IPublicKey | IPublicKey[]
	) => Buffer;
	decryptThenVerify: (
		cipherData: string | Buffer, decryptionKey: IPrivateKey, verificationKey: IPublicKey | IPublicKey[]
	) => Buffer;
}
