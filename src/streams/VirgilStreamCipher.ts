import { VirgilPublicKey } from '../VirgilPublicKey';
import { toArray } from '../utils/toArray';
import { validatePublicKeysArray } from '../validators';
import { VirgilStreamCipherBase } from './VirgilStreamCipherBase';
import { Data } from './../interfaces';
import { DATA_SIGNATURE_KEY } from '../common/constants';
import { anyToBuffer, StringEncoding } from '../utils/anyToBuffer';

/**
 * `VirgilStreamCipher` constructor `options` parameter.
 */
export interface VirgilStreamCipherOptions {
	/**
	 *  Optionally add a signature of plain data to the encrypted stream.
	 */
	signature?: Data;
	/**
	 * If `signature` is a string,
	 * specifies its encoding, otherwise is ignored. Default is 'base64'.
	 */
	encoding?: StringEncoding;
}

/**
 * Class responsible for encryption of streams of data.
 */
export class VirgilStreamCipher extends VirgilStreamCipherBase {
	/**
	 * Initializes a new instance of `VirgilStreamCipher`.
	 * `VirgilStreamCipher` objects are not meant to be created with the `new`
	 * operator, use {@link VirgilCrypto.createStreamCipher} to create an
	 * instance.
	 *
	 * @internal
	 *
	 * @param {VirgilPublicKey|VirgilPublicKey[]} publicKeys - A single
	 * {@link VirgilPublicKey} or an array of {@link VirgilPublicKey}'s to
	 * to encrypt the data with.
	 * @param {VirgilStreamCipherOptions} [options] - `VirgilStreamCipherOptions` object.
	 */
	constructor(
		publicKeys: VirgilPublicKey | VirgilPublicKey[],
		options?: VirgilStreamCipherOptions
	) {
		const publicKeyArr = toArray(publicKeys);
		validatePublicKeysArray(publicKeyArr);

		super();

		for (const { identifier, key } of publicKeyArr) {
			this.seqCipher.addKeyRecipientSafe(identifier, key);
		}

		if (options && options.signature) {
			const signatureKey = Buffer.from(DATA_SIGNATURE_KEY);
			const customParams = this.seqCipher.customParams();
			const encoding = options.encoding ? options.encoding : 'base64'
			customParams.setDataSafe(signatureKey, anyToBuffer(options.signature, encoding));
		}
	}

	/**
	 * Starts sequential encryption process following the algorithm below:
	 *
	 * 1. Generates random AES-256 key - KEY1
	 * 2. Generates ephemeral keypair for each recipient public key
	 * 3. Uses Diffie-Hellman to obtain shared secret with each recipient
	 *    public key & ephemeral private key
	 * 4. Computes KDF to obtain AES-256 key - KEY2 - from shared secret for
	 *    each recipient
	 * 5. Encrypts KEY1 with KEY2 using AES-256-CBC for each recipient
	 * 6. Returns the ASN.1 structure containing the encrypted KEY2 for each
	 *    recipient public key (content_info)
	 *
	 * The data passed to the {@link VirgilStreamCipher.update} method after
	 * this method is called will be encrypted with the KEY1
	 */
	start () {
		this.ensureLegalState();
		return this.seqCipher.startEncryptionSafe();
	}
}
