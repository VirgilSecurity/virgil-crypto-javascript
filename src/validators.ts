import { VirgilPrivateKey } from './VirgilPrivateKey';
import { VirgilPublicKey } from './VirgilPublicKey';
import { hasPrivateKeyBytes } from './privateKeyUtils';

/**
 * @hidden
 */
export function validatePrivateKey(privateKey: VirgilPrivateKey, label: string = 'privateKey') {
	if (privateKey == null || !Buffer.isBuffer(privateKey.identifier) || !hasPrivateKeyBytes(privateKey)) {
		throw new TypeError(`\`${label}\` is not a VirgilPrivateKey.`);
	}
}

/**
 * @hidden
 */
export function validatePublicKey(publicKey: VirgilPublicKey, label: string = 'publicKey') {
	if (publicKey == null || !Buffer.isBuffer(publicKey.identifier) || !Buffer.isBuffer(publicKey.key)) {
		throw new TypeError(`\`${label}\` is not a VirgilPublicKey.`);
	}
}

/**
 * @hidden
 */
export function validatePublicKeysArray(publicKeys: VirgilPublicKey[], label: string = 'publicKeys') {
	if (publicKeys.length === 0) {
		throw new TypeError(`\`${label}\` array must not be empty.`)
	}

	publicKeys.forEach(pubkey => validatePublicKey(pubkey));
}
