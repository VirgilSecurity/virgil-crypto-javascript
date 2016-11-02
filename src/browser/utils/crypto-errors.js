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
