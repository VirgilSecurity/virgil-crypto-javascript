import VirgilCrypto from './utils/crypto-module';
import * as u from './utils/crypto-utils';

export function obfuscate (value, salt, algorithm, iterations) {
	iterations = iterations || 2048;
	algorithm = algorithm || VirgilCrypto.VirgilHashAlgorithm.SHA384;
	var pbkdf = new VirgilCrypto.VirgilPBKDF(u.toByteArray(salt), iterations);
	pbkdf.setHashAlgorithm(algorithm);
	return u.byteArrayToBuffer(pbkdf.derive(u.toByteArray(value), 0)).toString('base64');
};
