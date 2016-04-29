import _ from 'lodash';
import uuid from 'node-uuid';
import sign from './sign';
import IdentityTypes from '../lib/identity-types';
import VirgilCrypto from './utils/crypto-module';
import * as CryptoUtils from './utils/crypto-utils';
import { throwVirgilError, throwValidationError } from './utils/crypto-errors';

export function generateValidationToken (identityValue, identityType, privateKey, privateKeyPassword) {
	if (!_.isString(identityValue)) {
		throw new TypeError('identityValue must be a string');
	}

	if (!(identityType in IdentityTypes)) {
		throw new TypeError('Invalid identityType');
	}

	if (!_.isString(privateKey)) {
		throw new TypeError('privateKey msut be string');
	}

	var uid = uuid.v4();
	var signature = sign(uid + identityType + identityValue, privateKey, privateKeyPassword);
	var validationToken = Buffer.concat([new Buffer(uid), new Buffer('.'), signature]);
	return validationToken.toString('base64');
};
