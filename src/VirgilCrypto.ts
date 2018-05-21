import { cryptoApi } from './node/api';
import { KeyPairType, HashAlgorithm, assert } from './common';
import { toArray } from './utils/toArray';
import { IPrivateKey, IPublicKey } from './interfaces';

export type KeyPair = {
	privateKey: VirgilPrivateKey,
	publicKey: VirgilPublicKey
}

const _privateKeys = new WeakMap();
const _setValue = WeakMap.prototype.set;
const _getValue = WeakMap.prototype.get;

export class VirgilPrivateKey implements IPrivateKey {
	identifier: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		setPrivateKeyBytes(this, key);
	}
}

export class VirgilPublicKey implements IPublicKey {
	identifier: Buffer;
	key: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		this.key = key;
	}
}

function getPrivateKeyBytes(privateKey: VirgilPrivateKey): Buffer {
	return _getValue.call(_privateKeys, privateKey);
}

function setPrivateKeyBytes(privateKey: VirgilPrivateKey, bytes: Buffer) {
	_setValue.call(_privateKeys, privateKey, bytes);
}


export interface VirgilCryptoOptions {
	useSha256Identifiers?: boolean;
	defaultKeyPairType?: KeyPairType;
}

export class VirgilCrypto {

	readonly useSha256Identifiers: boolean;

	readonly defaultKeyPairType: KeyPairType;

	constructor (
		{ useSha256Identifiers = false, defaultKeyPairType = KeyPairType.Default }: VirgilCryptoOptions = {}
	) {
		this.useSha256Identifiers = useSha256Identifiers;
		this.defaultKeyPairType = defaultKeyPairType;
	}

	generateKeys(type?: KeyPairType) {
		type = type != null ? type : this.defaultKeyPairType;

		const keyPair = cryptoApi.generateKeyPair({ type });
		const publicKeyDer = cryptoApi.publicKeyToDer(keyPair.publicKey);
		const privateKeyDer = cryptoApi.privateKeyToDer(keyPair.privateKey);
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);

		return {
			privateKey: new VirgilPrivateKey(identifier, privateKeyDer),
			publicKey: new VirgilPublicKey(identifier, publicKeyDer)
		};
	}

	importPrivateKey(rawPrivateKey: Buffer|string, password?: string) {
		assert(
			Buffer.isBuffer(rawPrivateKey) || typeof rawPrivateKey === 'string',
			'Cannot import private key. `rawPrivateKey` must be a Buffer or string in base64'
		);

		rawPrivateKey = Buffer.isBuffer(rawPrivateKey) ? rawPrivateKey : Buffer.from(rawPrivateKey, 'base64');

		if (password) {
			rawPrivateKey = cryptoApi.decryptPrivateKey(
				rawPrivateKey, Buffer.from(password, 'utf8')
			);
		}

		const privateKeyDer = cryptoApi.privateKeyToDer(rawPrivateKey);
		const publicKeyDer = cryptoApi.extractPublicKey(privateKeyDer);
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);

		return new VirgilPrivateKey(identifier, privateKeyDer);
	}

	exportPrivateKey(privateKey: VirgilPrivateKey, password?: string) {
		const privateKeyValue = getPrivateKeyBytes(privateKey);
		assert(privateKeyValue !== undefined, 'Cannot export private key. `privateKey` is invalid');

		if (password == null) {
			return privateKeyValue;
		}

		return cryptoApi.encryptPrivateKey(privateKeyValue, Buffer.from(password, 'utf8'));
	}

	importPublicKey(rawPublicKey: Buffer|string) {
		assert(
			Buffer.isBuffer(rawPublicKey) || typeof rawPublicKey === 'string',
			'Cannot import public key. `rawPublicKey` must be a Buffer'
		);

		rawPublicKey = Buffer.isBuffer(rawPublicKey) ? rawPublicKey : Buffer.from(rawPublicKey, 'base64');
		const publicKeyDer = cryptoApi.publicKeyToDer(rawPublicKey);
		const identifier = this.calculateKeypairIdentifier(publicKeyDer);
		return new VirgilPublicKey(identifier, publicKeyDer);
	}

	exportPublicKey(publicKey: VirgilPublicKey) {
		assert(
			publicKey != null && publicKey.key != null,
			'Cannot import public key. `publicKey` is invalid'
		);

		return publicKey.key;
	}

	encrypt(data: string|Buffer, publicKey: VirgilPublicKey|VirgilPublicKey[]) {
		assert(
			typeof data === 'string' || Buffer.isBuffer(data),
			'Cannot encrypt. `data` must be a string or Buffer'
		);

		const publicKeys = toArray(publicKey);
		assert(
			publicKeys.length > 0,
			'Cannot encrypt. `publicKey` must not be empty'
		);

		data = Buffer.isBuffer(data) ? data : Buffer.from(data);

		return cryptoApi.encrypt(data, publicKeys!);
	}

	decrypt(encryptedData: string|Buffer, privateKey: VirgilPrivateKey) {
		assert(
			typeof encryptedData === 'string' || Buffer.isBuffer(encryptedData),
			'Cannot decrypt. `data` must be a Buffer or a string in base64'
		);

		encryptedData = Buffer.isBuffer(encryptedData) ? encryptedData : Buffer.from(encryptedData, 'base64');
		const privateKeyValue = getPrivateKeyBytes(privateKey);
		assert(privateKeyValue !== undefined, 'Cannot decrypt. `privateKey` is invalid');
		return cryptoApi.decrypt(encryptedData, {
			identifier: privateKey.identifier,
			key: privateKeyValue
		});
	}

	calculateHash(data: Buffer|string, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
		assert(Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot calculate hash. `data` must be a Buffer or a string in base64');

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
		return cryptoApi.hash(data, algorithm);
	}

	extractPublicKey(privateKey: VirgilPrivateKey) {
		const privateKeyValue = getPrivateKeyBytes(privateKey);

		assert(
			privateKeyValue !== undefined,
			'Cannot extract public key. `privateKey` is invalid'
		);

		const publicKey = cryptoApi.extractPublicKey(privateKeyValue);
		return new VirgilPublicKey(privateKey.identifier, publicKey);
	}

	calculateSignature(data: Buffer|string, privateKey: VirgilPrivateKey) {
		assert(
			Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot calculate signature. `data` must be a Buffer or a string'
		);

		const privateKeyValue = getPrivateKeyBytes(privateKey);

		assert(
			privateKeyValue !== undefined,
			'Cannot calculate signature. `privateKey` is invalid'
		);

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

		return cryptoApi.sign(data, { key: privateKeyValue });
	}

	verifySignature(data: Buffer|string, signature: Buffer|string, publicKey: VirgilPublicKey) {
		assert(
			Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot verify signature. `data` must be a Buffer or a string'
		);

		assert(
			Buffer.isBuffer(signature) || typeof signature === 'string',
			'Cannot verify signature. `signature` must be a Buffer or a string'
		);

		assert(
			publicKey != null && Buffer.isBuffer(publicKey.key),
			'Cannot verify signature. `publicKey` is invalid'
		);

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
		signature = Buffer.isBuffer(signature) ? signature : Buffer.from(signature, 'base64');


		return cryptoApi.verify(data, signature, publicKey);
	}

	signThenEncrypt(
		data: Buffer|string,
		signingKey: VirgilPrivateKey,
		encryptionKey: VirgilPublicKey|VirgilPublicKey[])
	{
		assert(
			Buffer.isBuffer(data) || typeof data === 'string',
			'Cannot sign then encrypt. `data` must be a Buffer or a string'
		);

		const signingKeyValue = getPrivateKeyBytes(signingKey);

		assert(signingKeyValue !== undefined, 'Cannot sign then encrypt. `signingKey` is invalid');

		data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

		const encryptionKeys = toArray(encryptionKey);
		assert(
			encryptionKeys.length > 0,
			'Cannot sign then encrypt. `encryptionKey` must not be empty'
		);

		return cryptoApi.signThenEncrypt(
			data,
			{
				identifier: signingKey.identifier,
				key: signingKeyValue
			},
			encryptionKeys!
		);
	}

	decryptThenVerify(
		cipherData: Buffer|string,
		decryptionKey: VirgilPrivateKey,
		verificationKey: VirgilPublicKey|VirgilPublicKey[]
	) {
		assert(
			Buffer.isBuffer(cipherData) || typeof cipherData === 'string',
			'Cannot decrypt then verify. `cipherData` must be a Buffer of a string in base64'
		);

		const verificationKeys = toArray(verificationKey);
		assert(
			verificationKeys.length > 0,
			'Cannot decrypt then verify. `verificationKey` must not be empty'
		);

		const decryptionKeyValue = getPrivateKeyBytes(decryptionKey);
		assert(
			decryptionKeyValue !== undefined,
			'Cannot decrypt then verify. `decryptionKey` is invalid'
		);

		cipherData = Buffer.isBuffer(cipherData) ? cipherData : Buffer.from(cipherData, 'base64');

		return cryptoApi.decryptThenVerify(
			cipherData,
			{
				identifier: decryptionKey.identifier,
				key: decryptionKeyValue
			},
			verificationKeys!
		);
	}

	private calculateKeypairIdentifier(publicKeyData: Buffer) {
		if (this.useSha256Identifiers) {
			return cryptoApi.hash(publicKeyData, HashAlgorithm.SHA256);
		} else {
			return cryptoApi.hash(publicKeyData, HashAlgorithm.SHA512).slice(0, 8);
		}
	}
}
