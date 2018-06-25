import { KeyPair, KeyPairType, HashAlgorithm, IVirgilCryptoWrapper } from './common';
import { toArray } from './utils/toArray';
import {
	VirgilPrivateKey as IVirgilPrivateKey,
	VirgilPublicKey as IVirgilPublicKey,
	IVirgilCrypto,
	VirgilCryptoOptions,
	VirgilKeyPair,
	Data
} from './interfaces';
import { anyToBuffer } from './utils/anyToBuffer';

const _privateKeys = new WeakMap();
const _setValue = WeakMap.prototype.set;
const _getValue = WeakMap.prototype.get;
const _hasValue = WeakMap.prototype.has;

/**
 * Dynamically generated class that implements the {@link IVirgilCrypto} interface
 */
export interface VirgilCryptoClass {
	new(options?: VirgilCryptoOptions): IVirgilCrypto;
}

/**
 * Represents a private key for operations with {@link IVirgilCrypto}.
 *
 * `VirgilPrivateKey` objects are not meant to be created directly using the `new` keyword.
 * Use the {@link IVirgilCrypto.generateKeys} and {@link IVirgilCrypto.importPrivateKey} methods
 * to create `VirgilPrivateKey` instances.
 *
 * @protected
 */
class VirgilPrivateKey implements IVirgilPrivateKey {
	/**
	 * Private key identifier. Note that the private key and its
	 * corresponding public key will have the same identifier.
	 * */
	identifier: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		setPrivateKeyBytes(this, key);
	}
}

/**
 * Represents a public key for operations with {@link IVirgilCrypto}.
 *
 * `VirgilPublicKey` objects are not meant to be created directly using the `new` keyword.
 * Use the {@link IVirgilCrypto.generateKeys} and {@link IVirgilCrypto.importPublicKey} methods
 * to create `VirgilPublicKey` instances.
 *
 * @protected
 */
class VirgilPublicKey implements IVirgilPublicKey {
	/**
	 * Public key identifier. Note that the public key and its
	 * corresponding private key will have the same identifier.
	 * */
	identifier: Buffer;

	/**
	 * The public key material. Unlike the private keys, the public
	 * key material is available as a property of the `PublicKey` object.
	 */
	key: Buffer;

	constructor(identifier: Buffer, key: Buffer) {
		this.identifier = identifier;
		this.key = key;
	}
}

/**
 * Gets the private key bytes of the given private key object from internal store.
 * @param {VirgilPrivateKey} privateKey - Private key object.
 * @returns {Buffer} - Private key bytes.
 *
 * @hidden
 */
function getPrivateKeyBytes(privateKey: VirgilPrivateKey): Buffer {
	return _getValue.call(_privateKeys, privateKey);
}

/**
 * Saves the private key bytes corresponding to the given private key object into
 * internal buffer.
 *
 * @param {VirgilPrivateKey} privateKey - Private key object.
 * @param {Buffer} bytes - Private key bytes.
 *
 * @hidden
 */
function setPrivateKeyBytes(privateKey: VirgilPrivateKey, bytes: Buffer) {
	_setValue.call(_privateKeys, privateKey, bytes);
}

/**
 * @hidden
 */
function validatePrivateKey(privateKey: VirgilPrivateKey, label: string = 'privateKey') {
	if (privateKey == null || !Buffer.isBuffer(privateKey.identifier) || !_hasValue.call(_privateKeys, privateKey)) {
		throw new TypeError(`\`${label}\` is not a VirgilPrivateKey.`);
	}
}

/**
 * @hidden
 */
function validatePublicKey(publicKey: VirgilPublicKey, label: string = 'publicKey') {
	if (publicKey == null || !Buffer.isBuffer(publicKey.identifier) || !Buffer.isBuffer(publicKey.key)) {
		throw new TypeError(`\`${label}\` is not a VirgilPublicKey.`);
	}
}

/**
 * @hidden
 */
function validatePublicKeysArray(publicKeys: VirgilPublicKey[], label: string = 'publicKeys') {
	if (publicKeys.length === 0) {
		throw new TypeError(`\`${label}\` array must not be empty.`)
	}

	publicKeys.forEach(pubkey => validatePublicKey(pubkey));
}

/**
 * Creates a class implementing the {@link IVirgilCrypto} interface.
 *
 * @hidden
 *
 * @param {IVirgilCryptoWrapper} cryptoWrapper
 * @returns {(options?: VirgilCryptoOptions) => VirgilCrypto}
 */
export function makeVirgilCryptoClass (cryptoWrapper: IVirgilCryptoWrapper)
	: VirgilCryptoClass {

	return class _VirgilCrypto implements IVirgilCrypto {
		public readonly useSha256Identifiers: boolean;
		public readonly defaultKeyPairType: KeyPairType;

		constructor({
			useSha256Identifiers = false,
			defaultKeyPairType = KeyPairType.Default
		}: VirgilCryptoOptions = {}) {
			this.useSha256Identifiers = useSha256Identifiers;
			this.defaultKeyPairType = defaultKeyPairType;
		}

		generateKeys(type?: KeyPairType) {
			type = type != null ? type : this.defaultKeyPairType;

			const keyPair = cryptoWrapper.generateKeyPair({ type });
			return this.wrapKeyPair(keyPair);
		}

		generateKeysFromKeyMaterial(keyMaterial: Data, type?: KeyPairType): VirgilKeyPair {
			type = type != null ? type : this.defaultKeyPairType;
			const keyMaterialBuf = anyToBuffer(keyMaterial, 'base64', 'keyMaterial');

			const keyPair = cryptoWrapper.generateKeyPairFromKeyMaterial({
				keyMaterial: keyMaterialBuf,
				type
			});
			return this.wrapKeyPair(keyPair);
		}

		importPrivateKey(rawPrivateKey: Data, password?: string) {
			let rawPrivateKeyBuf = anyToBuffer(rawPrivateKey, 'base64', 'rawPrivateKey');

			if (password) {
				rawPrivateKeyBuf = cryptoWrapper.decryptPrivateKey(
					rawPrivateKeyBuf,
					Buffer.from(password, 'utf8')
				);
			}

			const privateKeyDer = cryptoWrapper.privateKeyToDer(rawPrivateKeyBuf);
			const publicKeyDer = cryptoWrapper.extractPublicKey(privateKeyDer);
			const identifier = this.calculateKeypairIdentifier(publicKeyDer);

			return new VirgilPrivateKey(identifier, privateKeyDer);
		}

		exportPrivateKey(privateKey: VirgilPrivateKey, password?: string) {
			validatePrivateKey(privateKey);
			const privateKeyValue = getPrivateKeyBytes(privateKey);

			if (password == null) {
				return privateKeyValue;
			}

			return cryptoWrapper.encryptPrivateKey(privateKeyValue, Buffer.from(password, 'utf8'));
		}

		importPublicKey(rawPublicKey: Data) {
			const rawPublicKeyBuf = anyToBuffer(rawPublicKey, 'base64', 'rawPublicKey');

			const publicKeyDer = cryptoWrapper.publicKeyToDer(rawPublicKeyBuf);
			const identifier = this.calculateKeypairIdentifier(publicKeyDer);
			return new VirgilPublicKey(identifier, publicKeyDer);
		}

		exportPublicKey(publicKey: VirgilPublicKey) {
			validatePublicKey(publicKey);
			return publicKey.key;
		}

		encrypt(data: Data, publicKey: VirgilPublicKey|VirgilPublicKey[]) {
			const dataBuf = anyToBuffer(data, 'utf8', 'data');
			const publicKeys = toArray(publicKey);

			validatePublicKeysArray(publicKeys);

			return cryptoWrapper.encrypt(dataBuf, publicKeys);
		}

		decrypt(encryptedData: Data, privateKey: VirgilPrivateKey) {
			const encryptedDataBuf = anyToBuffer(encryptedData, 'base64', 'encryptedData');
			validatePrivateKey(privateKey);
			const privateKeyValue = getPrivateKeyBytes(privateKey);

			return cryptoWrapper.decrypt(encryptedDataBuf, {
				identifier: privateKey.identifier,
				key: privateKeyValue
			});
		}

		calculateHash(data: Data, algorithm: HashAlgorithm = HashAlgorithm.SHA256) {
			const dataBuf = anyToBuffer(data, 'utf8', 'data');
			return cryptoWrapper.hash(dataBuf, algorithm);
		}

		extractPublicKey(privateKey: VirgilPrivateKey) {
			validatePrivateKey(privateKey);
			const privateKeyValue = getPrivateKeyBytes(privateKey);
			const publicKey = cryptoWrapper.extractPublicKey(privateKeyValue);
			return new VirgilPublicKey(privateKey.identifier, publicKey);
		}

		calculateSignature(data: Data, privateKey: VirgilPrivateKey) {
			const dataBuf = anyToBuffer(data, 'utf8', 'data');
			validatePrivateKey(privateKey);
			const privateKeyValue = getPrivateKeyBytes(privateKey);

			return cryptoWrapper.sign(dataBuf, { key: privateKeyValue });
		}

		verifySignature(data: Data, signature: Data, publicKey: VirgilPublicKey) {
			const dataBuf = anyToBuffer(data, 'utf8', 'data');
			const signatureBuf = anyToBuffer(signature, 'base64', 'signature');
			validatePublicKey(publicKey);

			return cryptoWrapper.verify(dataBuf, signatureBuf, publicKey);
		}

		signThenEncrypt(
			data: Data,
			privateKey: VirgilPrivateKey,
			publicKey: VirgilPublicKey|VirgilPublicKey[])
		{
			const dataBuf = anyToBuffer(data, 'utf8', 'data');
			validatePrivateKey(privateKey);
			const signingKeyValue = getPrivateKeyBytes(privateKey);

			const publicKeys = toArray(publicKey);
			validatePublicKeysArray(publicKeys);

			return cryptoWrapper.signThenEncrypt(
				dataBuf,
				{
					identifier: privateKey.identifier,
					key: signingKeyValue
				},
				publicKeys
			);
		}

		decryptThenVerify(
			cipherData: Data,
			privateKey: VirgilPrivateKey,
			publicKey: VirgilPublicKey|VirgilPublicKey[]
		) {
			const cipherDataBuf = anyToBuffer(cipherData, 'base64', 'cipherData');

			const publicKeys = toArray(publicKey);
			validatePublicKeysArray(publicKeys);

			validatePrivateKey(privateKey);
			const decryptionKeyValue = getPrivateKeyBytes(privateKey);

			return cryptoWrapper.decryptThenVerify(
				cipherDataBuf,
				{
					identifier: privateKey.identifier,
					key: decryptionKeyValue
				},
				publicKeys
			);
		}

		getRandomBytes (length: number): Buffer {
			return cryptoWrapper.getRandomBytes(length);
		}

		/**
		 * Calculates the keypair identifier form the public key material.
		 * Takes first 8 bytes of SHA512 of public key DER if `useSHA256Identifiers=false`
		 * and SHA256 of public key der if `useSHA256Identifiers=true`
		 *
		 * @hidden
		 *
		 * @param {Buffer} publicKeyData - Public key material.
		 * @returns {Buffer} Key pair identifier
		 */
		private calculateKeypairIdentifier(publicKeyData: Buffer): Buffer {
			if (this.useSha256Identifiers) {
				return cryptoWrapper.hash(publicKeyData, HashAlgorithm.SHA256);
			} else {
				return cryptoWrapper.hash(publicKeyData, HashAlgorithm.SHA512).slice(0, 8);
			}
		}

		/**
		 * Wraps binary private and public keys into {@link VirgilKeyPair} object.
		 *
		 * @hidden
		 *
		 * @param {KeyPair} keyPair
		 * @returns {VirgilKeyPair}
		 */
		private wrapKeyPair (keyPair: KeyPair) {
			const privateKeyDer = cryptoWrapper.privateKeyToDer(keyPair.privateKey);
			const publicKeyDer = cryptoWrapper.publicKeyToDer(keyPair.publicKey);
			const identifier = this.calculateKeypairIdentifier(publicKeyDer);

			return {
				privateKey: new VirgilPrivateKey(identifier, privateKeyDer),
				publicKey: new VirgilPublicKey(identifier, publicKeyDer)
			};
		}
	}
}
