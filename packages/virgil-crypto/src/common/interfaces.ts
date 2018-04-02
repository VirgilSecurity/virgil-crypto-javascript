export type EncryptionKey = {
	identifier: Buffer,
	publicKey: Buffer
}

export type DecryptionKey = {
	identifier: Buffer,
	privateKey: Buffer,
	privateKeyPassword?: Buffer
}
