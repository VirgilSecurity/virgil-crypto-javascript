import uuid from 'node-uuid';
import sign from './sign';
import { throwValidationError } from './utils/crypto-errors';

export function generateValidationToken (identityValue, identityType, privateKey, privateKeyPassword) {
	if (typeof identityValue !== 'string') {
		throwValidationError('00001', { arg: 'identityValue', type: 'string' });
	}

	const uid = uuid.v4();
	const signature = sign(
		new Buffer(uid + identityType + identityValue),
		privateKey,
		privateKeyPassword);
	const validationToken = Buffer.concat([new Buffer(uid), new Buffer('.'), new Buffer(signature.toString('base64'))]);
	return validationToken.toString('base64');
}
