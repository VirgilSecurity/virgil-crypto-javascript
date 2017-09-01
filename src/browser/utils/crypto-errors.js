import VirgilCryptoError from '../../lib/Error';

export const errors = {
	'00000': _ => 'An error occurred',
	'00001': ({arg, type}) => `The "${arg}" must be a "${type}"`,
	'00002': ({arg, type}) => `The "${arg}" must be "${type}"`,
	'10000': ({error}) => error,
	'90001': ({error}) => `Unable to ENCRYPT the given data. ${error}`,
	'90002': ({error}) => `Unable to DECRYPT the given data. ${error}`,
	'90003': ({error}) => `Unable to ENCRYPT the given data. ${error}`,
	'90004': ({error}) => `Unable to DECRYPT the given data. ${error}`,
	'90005': ({error}) => `Unable to SIGN the given data. ${error}`,
	'90006': ({error}) => `Unable to VERIFY the given data. ${error}`,
	'90007': ({error}) => `Unable to generate key pair using the given password. ${error}`,
	'90008': ({error}) => `Unable to ENCRYPT the given data using given recipients. ${error}`,
	'90009': ({error}) => `Unable to encrypt the given private key. ${error}`,
	'90010': ({error}) => `Unable to decrypt the given private key. ${error}`
};

export function throwVirgilError (code, tokens) {
	throw new VirgilCryptoError((errors[code])(tokens), code);
}

export function throwValidationError (code, tokens) {
	throwVirgilError(code, tokens);
}

export function checkIsBuffer (arg, name) {
	if (!Buffer.isBuffer(arg)) {
		throwVirgilError('00001', { arg: name, type: 'Buffer' });
	}
}

export function assert(condition, text) {
	if (!condition) {
		throw new VirgilCryptoError(text, '10000');
	}
}

export function generateErrorFromNativeError(err) {
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
	// "Module: virgil/crypto. Error code: {code}. {name}. {message}."
	const parts = virgilCryptoMessage.split(/\s*\.\s*/);
	if (parts.length === 1) {
		// Error message didn't match what we expected.
		return err;
	}

	const [, code, name, message ] = parts;
	const virgilError = new VirgilCryptoError();
	virgilError.code = code.split(/\s*:\s*/)[1];
	virgilError.message = message + '.';
	virgilError.name = name;

	return virgilError;
}
