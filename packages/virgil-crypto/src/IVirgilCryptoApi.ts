import { KeyPairType, DecryptionKey, EncryptionKey } from 'virgil-crypto-utils';

export interface IVirgilCryptoApi {
	generateKeyPair(options: { type?: KeyPairType, password?: Buffer }): { privateKey: Buffer, publicKey: Buffer };
	privateKeyToDer(privateKey: Buffer, password?: Buffer): Buffer;
	publicKeyToDer(publicKey: Buffer): Buffer;
	hash(data: Buffer, algorithm?: string): Buffer;
	encrypt(data: Buffer, encryptionKey: EncryptionKey|EncryptionKey[]): Buffer;
	decrypt(encryptedData: Buffer, decryptionKey: DecryptionKey): Buffer;
	decryptPrivateKey(privateKey: Buffer, password: Buffer): Buffer;
	extractPublicKey(privateKey: Buffer): Buffer;
	encryptPrivateKey(privateKey: Buffer, password: Buffer): Buffer;
	sign(data: Buffer, privateKey: Buffer, privateKeyPassword?: Buffer): Buffer;
	verify(data: Buffer, signature: Buffer, publicKey: Buffer): boolean;
}
