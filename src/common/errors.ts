/**
 * Custom Error class.
 * @hidden
 */
export class VirgilCryptoError extends Error {
	name: string;

	constructor(message: string, name: string = 'VirgilCryptoError') {
		super();
		Object.setPrototypeOf(this, VirgilCryptoError.prototype);
		this.message = message;
		this.name = name;
	}

	toString() {
		return `${this.name}: ${this.message}.`;
	}
}

/**
 * An error that is thrown when digital signature validation fails
 * during {@link IVirgilCrypto.decryptThenVerify} method execution.
 */
export class IntegrityCheckFailedError extends VirgilCryptoError {
	constructor(message: string) {
		super(message, 'IntegrityCheckFailedError');
	}
}

/**
 * An error that is thrown when weak key material is passed to the
 * {@link IVirgilCrypto.generateKeysFromKeyMaterial} method.
 * The key material is considered weak if it's less than 32 bytes.
 */
export class WeakKeyMaterialError extends VirgilCryptoError {
	constructor(message: string) {
		super(message, 'WeakKeyMaterialError');
	}
}

/**
 * Throws an error with `message` if `condition` is `false`.
 * @hidden
 * @param {boolean} condition - Condition to check.
 * @param {string} message - Error message.
 */
export function assert(condition: boolean, message: string) {
	if (!condition) {
		throw new VirgilCryptoError(message);
	}
}
