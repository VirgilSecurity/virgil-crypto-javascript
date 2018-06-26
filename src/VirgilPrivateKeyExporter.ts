import { IPrivateKey, IVirgilCrypto, VirgilPrivateKey } from './interfaces';

/**
 * Class implementing operations required to convert between raw
 * private key material and private key objects and vice versa
 * (i.e. the `IPrivateKeyExporter` interface from
 * {@link https://bit.ly/2KFRmT8|virgil-sdk}), using {@link IVirgilCrypto}.
 */
export class VirgilPrivateKeyExporter {

	/**
	 * Initializes the new `VirgilPrivateKeyExporter`
	 * @param {IVirgilCrypto} virgilCrypto - VirgilCrypto instance, providing
	 * implementation of crypto operations.
	 * @param {string} [password] - Optional password used to encrypt the key
	 * before export and decrypt before import.
	 * NOTE: do NOT use the default (no password), unless your storage/transport
	 * channel is secure.
	 */
	constructor(private readonly virgilCrypto: IVirgilCrypto, public password?: string) {
		if (virgilCrypto == null) throw new Error('`virgilCrypto` is required');
	}

	/**
	 * Exports private key material in DER format from the given private key object.
	 *
	 * @param {IPrivateKey} key - The private key object to export the key material from.
	 * @returns {Buffer} - The private key material in DER format.
	 */
	exportPrivateKey (key: IPrivateKey) {
		return this.virgilCrypto.exportPrivateKey(key as VirgilPrivateKey, this.password);
	}

	/**
	 * Creates a {@link VirgilPrivateKey} object from private key material in PEM or DER format.
	 *
	 * @param {Buffer | string} keyData - The private key material. If `keyData` is
	 * a string, base64 encoding is assumed.
	 * @returns {VirgilPrivateKey} The private key object.
	 */
	importPrivateKey (keyData: Buffer|string) {
		return this.virgilCrypto.importPrivateKey(keyData, this.password);
	}
}
