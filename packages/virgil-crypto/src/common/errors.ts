export class VirgilCryptoError extends Error {
	public name: string = 'VirgilCryptoError';
	public code?: string;

	constructor(message: string, code?: string, name?: string) {
		super(message);
		Object.setPrototypeOf(this, VirgilCryptoError.prototype);
		this.code = code;
		if (name !== undefined) {
			this.name = name;
		}
	}

	toString() {
		return `${this.name}: ${this.code !== undefined ? this.code : 'UNKNOWN'}: ${this.message}.`;
	}
}

export function errorFromNativeError(err: Error) {
	if (!(err instanceof Error)) {
		return err;
	}

	// Error messages from native virgil-crypto consist of two
	// lines: one from VirgilCrypto itself, another one from
	// mbed-tls. We are only interested in the former since it
	// contains a friendlier message.
	const virgilCryptoMessage = err.message.split(/\r?\n/)[0];
	if (!virgilCryptoMessage) {
		return err;
	}

	// Expected message format is as follows:
	// "Module: virgil/crypto. Error code: {code}. {message}."
	const parts = virgilCryptoMessage.split(/\s*\.\s*/);
	if (parts.length === 1) {
		// Error message didn't match what we expected.
		return err;
	}

	const [, code, message ] = parts;
	return new VirgilCryptoError(message, code, name);
}

export function assert(condition: boolean, message: string) {
	if (!condition) {
		throw new VirgilCryptoError(message);
	}
}
