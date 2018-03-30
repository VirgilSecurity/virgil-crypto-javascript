import { KeyPairType } from 'virgil-crypto-utils';
import { IVirgilCryptoApi } from './IVirgilCryptoApi';

export type KeyPair = {
	privateKey: PrivateKey,
	publicKey: PublicKey
}

const _privateKeys = new WeakMap();
const _setPrivateKeyValue = WeakMap.prototype.set;
// const _getPrivateKeyValue = WeakMap.prototype.get;

export class PrivateKey {
	identifier: Buffer;

	constructor(identifier: Buffer, value: Buffer) {
		this.identifier = identifier;
		_setPrivateKeyValue.call(_privateKeys, this, value);
	}
}
export class PublicKey {
	identifier: Buffer;
	value: Buffer;

	constructor(identifier: Buffer, value: Buffer) {
		this.identifier = identifier;
		this.value = value;
	}
}

export function createVirgilCrypto (cryptoApi: IVirgilCryptoApi) {

	return {
		generateKeys,
		// importPrivateKey,
		// importPublicKey,
		// exportPrivateKey,
		// exportPublicKey,
		// extractPublicKey,
		// encrypt,
		// decrypt,
		// calculateSignature,
		// verifySignature,
		// calculateHash
	};

	/**
	 * Generates a new key pair.
	 *
	 * @param {KeyPairType} [type] - Optional type of the key pair.
	 * 			See {code: KeyPairType} for available options.
	 * @returns {KeyPair} - The newly generated key pair.
	 * */
	function generateKeys(type?: KeyPairType) {
		const keyPair = cryptoApi.generateKeyPair({ type });
		const publicKeyDer = cryptoApi.publicKeyToDer(keyPair.publicKey);
		const privateKeyDer = cryptoApi.privateKeyToDer(keyPair.privateKey);
		const identifier = cryptoApi.hash(publicKeyDer);

		return {
			privateKey: new PrivateKey(identifier, privateKeyDer),
			publicKey: new PublicKey(identifier, publicKeyDer)
		};
	}
}
