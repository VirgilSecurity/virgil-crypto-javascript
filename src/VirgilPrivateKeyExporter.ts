import { VirgilCrypto, VirgilPrivateKey } from './VirgilCrypto';
import { IPrivateKey } from './interfaces';

/**
 * Class implementing operations required to convert between raw
 * private key material and private key objects and vice versa
 * (i.e. the `IPrivateKeyExporter` interface from
 * {@link https://bit.ly/2KFRmT8|virgil-sdk}), using {@link VirgilCrypto}.
 */
export class VirgilPrivateKeyExporter {
	public password?: string;
	private readonly crypto: VirgilCrypto;

	/**
	 * Initializes the new `VirgilPrivateKeyExporter`
	 * @param {VirgilCrypto} virgilCrypto - VirgilCrypto instance, providing
	 * implementation of crypto operations. Optional. A new instance will be
	 * created automatically if this parameter is omitted.
	 * @param {string} [password] - Optional password used to encrypt the key
	 * before export and decrypt before import.
	 * NOTE: do NOT use the default (no password), unless your storage/transport
	 * channel is secure.
	 */
	constructor(virgilCrypto?: VirgilCrypto, password?: string) {
		if (typeof virgilCrypto === 'string' && typeof password === 'undefined') {
			password = virgilCrypto;
			virgilCrypto = undefined;
		}

		this.crypto = virgilCrypto || new VirgilCrypto();
		this.password = password;
	}

	/**
	 * Exports private key material in DER format from the given private key object.
	 *
	 * @param {IPrivateKey} key - The private key object to export the key material from.
	 * @returns {Buffer} - The private key material in DER format.
	 */
	exportPrivateKey (key: IPrivateKey) {
		return this.crypto.exportPrivateKey(key as VirgilPrivateKey, this.password);
	}

	/**
	 * Creates a {@link VirgilPrivateKey} object from private key material in PEM or DER format.
	 *
	 * @param {Buffer | string} keyData - The private key material. If `keyData` is
	 * a string, base64 encoding is assumed.
	 * @returns {VirgilPrivateKey} The private key object.
	 */
	importPrivateKey (keyData: Buffer|string) {
		return this.crypto.importPrivateKey(keyData, this.password);
	}
}
